// Package marshal is the bubble's people: who they are, which panel each is
// signed in at, and what they may do. SPEC.txt §24.
//
// A person signs in with a key: a passkey on their phone, or a panel's own
// key. marshal keeps the public halves, hands out challenges, and checks
// the answers; it holds nothing that could sign anyone in. What it grants
// the hub enforces, by the tickets marshal signs (SECURITY.txt §5, §6).
package marshal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	log "log/slog"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MrZloHex/monolink"
	auth "github.com/MrZloHex/monolink/marshal"
)

// NodeName is marshal's address on the bus.
const NodeName = auth.Node

const (
	challengeTTL   = time.Minute         // how long a challenge may be answered
	maxChallenges  = 64                  // outstanding at once, per panel: the internet's MONOWEB cannot starve MONOVIEW
	inviteTTL      = time.Hour           // how long an invitation may be taken up
	maxInvites     = 16                  // outstanding at once, bubble-wide
	maxInvitesEach = 3                   // outstanding at once, per inviter
	maxPeople      = monolink.MaxArgs    // GET:USERS answers every name in one frame
	maxKeys        = 8                   // per person
	maxSessions    = 16                  // per person; one more ends the oldest
	maxSessionAge  = 30 * 24 * time.Hour // however faithfully a session is renewed
	freshSignIn    = 5 * time.Minute     // how recent the sign-in behind an invitation must be
	freeFailures   = 5                   // wrong codes, from one panel for one name, before more are answered BUSY
	baseLockout    = 30 * time.Second
	maxLockout     = 15 * time.Minute
	forgetFailures = time.Hour // wrong codes, forgotten after this quiet
	printTimeout   = 5 * time.Second
	deliverEvery   = 5 * time.Second // how often ended tickets the hub has not acknowledged are sent again
)

// Options configures a Marshal.
type Options struct {
	TTL       time.Duration // how long a session lasts unused
	Printer   string        // node that prints the enrolment code; "" logs it
	Version   string
	TicketKey ed25519.PrivateKey // signs tickets for the hub (SECURITY.txt §5); none, and none are signed
	// Site is whom passkeys are made for: the site's domain and the origins
	// its pages come from. Without one, no passkey signs in.
	Site auth.RelyingParty
}

type challenge struct {
	panel   string
	expires time.Time
}

type invite struct {
	name    string
	by      string
	byGen   int  // the inviter's key generation then: a key of theirs removed since voids it
	fresh   bool // name was nobody's: it makes someone new, and adds no key to whoever has the name by then
	expires time.Time
}

// Marshal answers for people, sessions and grants.
type Marshal struct {
	c     *monolink.Client
	store *Store
	opt   Options
	now   func() time.Time

	users, sessions, enrolling, people *monolink.Property

	mu         sync.Mutex
	st         *State
	enrolCode  string // set while nobody can sign in
	challenges map[string]challenge
	invites    map[string]invite    // by hashCode
	codes      map[string]*lockout  // wrong codes: the enrolment code's by panel, invitations' by panel and name
	ended      map[string]time.Time // by person: the tickets signed until then are void
	lastIssued map[string]time.Time // by person: when their latest ticket says it was signed
	wake       chan struct{}        // an ended ticket to tell the hub about

	pubMu  sync.Mutex // one publish at a time, so an older snapshot never overwrites a newer one
	ending *monolink.Property
}

type lockout struct {
	failures int
	last     time.Time // the latest wrong code
	until    time.Time
}

// New loads the state and attaches marshal's object model to c. Register
// m.Cmd as c's "*" handler, then Connect, then Start.
func New(c *monolink.Client, store *Store, opt Options) (*Marshal, error) {
	st, err := store.Load()
	if err != nil {
		return nil, err
	}
	if opt.TTL <= 0 {
		opt.TTL = time.Hour
	}
	m := &Marshal{c: c, store: store, opt: opt, now: time.Now, st: st,
		challenges: map[string]challenge{}, invites: map[string]invite{}, codes: map[string]*lockout{},
		ended: map[string]time.Time{}, lastIssued: map[string]time.Time{}, wake: make(chan struct{}, 1)}
	// Tickets ended before a restart stay ended: none is signed at or before a
	// cutoff the hub may not have heard yet.
	for p, since := range st.Ending {
		m.ended[p] = since
	}

	// Not USERS or SESSIONS: those are nouns marshal answers with lists, and
	// a property of the same name would be served in their place.
	node := monolink.NewNode(c, monolink.NodeInfo{Class: monolink.ClassNode, Product: "marshal", Version: opt.Version})
	m.users = node.Prop("USERS.COUNT", monolink.Int(0, 1000), "people in the bubble")
	m.sessions = node.Prop("SESSIONS.COUNT", monolink.Int(0, 100000), "sessions open")
	m.enrolling = node.Prop("ENROLLING", monolink.Bool(), "nobody can sign in yet; an enrolment code is out")
	// Who is in the bubble, readable by any node — synapse must know whom a
	// message can go to. Names are no secret inside the household; what
	// each may do is, and GET:USERS stays behind MARSHAL.*.
	m.people = node.Prop("PEOPLE", monolink.Str(0), "the people of the bubble, a record of names")
	m.ending = node.Prop("TICKETS.ENDING", monolink.Int(0, 100000), "people whose ended tickets the hub has not yet acknowledged")
	// A hub connected to again may have missed a cutoff, or restarted since.
	c.OnConnect(func(*monolink.Client) { m.kick() })

	if !m.anyKey() {
		if m.enrolCode, err = newCode(); err != nil {
			return nil, err
		}
	}
	m.publish()
	return m, nil
}

// Start runs what marshal does unasked: telling the hub about ended tickets,
// putting the enrolment code where the owner will find it, and forgetting
// expired sessions.
func (m *Marshal) Start(ctx context.Context) {
	go m.deliverEndings(ctx)
	if code := m.EnrolCode(); code != "" {
		go m.announceEnrolment(ctx, code)
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.mu.Lock()
				if m.expire(m.now()) {
					m.save()
				}
				m.mu.Unlock()
				m.publish()
			}
		}
	}()
}

// EnrolCode is the code that makes the first person, or "" once someone
// can sign in.
func (m *Marshal) EnrolCode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enrolCode
}

// anyKey reports whether anyone can sign in at all. Until someone can,
// enrolment is open — in a new bubble, and in one whose state is from
// before keys.
func (m *Marshal) anyKey() bool {
	for _, u := range m.st.Users {
		if len(u.Keys) > 0 {
			return true
		}
	}
	return false
}

// ─── codes ───────────────────────────────────────────────────────────

// Crockford's base32: no I, L, O or U, so what is printed is what gets typed.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newCode is 60 random bits as XXXX-XXXX-XXXX: the enrolment code, or an
// invitation. Not guessable over a bus, lockout or none (see lockoutFor).
func newCode() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	var s strings.Builder
	for i, x := range b {
		if i > 0 && i%4 == 0 {
			s.WriteByte('-')
		}
		s.WriteByte(crockford[x&31])
	}
	return s.String(), nil
}

// normaliseCode forgives how a person types a code: case, dashes, spaces,
// and the letters Crockford leaves out for looking like digits.
func normaliseCode(s string) string {
	return strings.NewReplacer("-", "", " ", "", "O", "0", "I", "1", "L", "1").Replace(strings.ToUpper(s))
}

// hashCode is what an invitation is filed under, so that looking one up
// takes no longer for a nearly right code than for a wrong one.
func hashCode(code string) string {
	h := sha256.Sum256([]byte(normaliseCode(code)))
	return hex.EncodeToString(h[:])
}

// lockoutFor is the count of wrong codes kept under key: a panel, for the
// enrolment code; a panel and the name it is for, for an invitation. Every
// browser on the internet is MONOWEB, so a stranger's guesses for one name
// are counted apart from everyone else's. It is forgotten after an hour's
// quiet, so typos add up to nothing over months.
//
// A right code is never refused for wrong ones before it. A code is 60
// random bits: at the hub's hundred frames a second a guesser needs some
// three hundred million years, so the count guards nothing a right code
// could be used for. What it does is answer a guesser BUSY, and name them in
// the log.
func (m *Marshal) lockoutFor(key string, now time.Time) *lockout {
	l := m.codes[key]
	if l == nil || (now.Sub(l.last) > forgetFailures && !now.Before(l.until)) {
		l = &lockout{}
		m.codes[key] = l
	}
	return l
}

// codesLocked refuses wrong codes under key while its lockout lasts, saying
// for how long.
func (m *Marshal) codesLocked(key string, now time.Time) error {
	if l := m.lockoutFor(key, now); now.Before(l.until) {
		return monolink.Fail(monolink.CodeBusy, strconv.Itoa(int(l.until.Sub(now).Seconds())+1))
	}
	return nil
}

// wrongCode counts a wrong code under key. After freeFailures, more wrong
// codes are answered BUSY, for twice as long each time, up to maxLockout.
func (m *Marshal) wrongCode(key string, now time.Time) error {
	if err := m.codesLocked(key, now); err != nil {
		return err
	}
	l := m.lockoutFor(key, now)
	l.failures++
	l.last = now
	if over := l.failures - freeFailures; over >= 0 {
		d := maxLockout
		if over < 10 {
			d = min(baseLockout<<over, maxLockout)
		}
		l.until = now.Add(d)
		log.Warn("CODES LOCKED OUT", "for", key, "lockout", d)
	}
	return monolink.Fail(monolink.CodeDenied, "")
}

// announceEnrolment prints the code, or writes it to the log when there is
// no printer to hand (SPEC §24).
func (m *Marshal) announceEnrolment(ctx context.Context, code string) {
	log.Info("ENROLMENT OPEN", "printer", m.opt.Printer)
	if m.opt.Printer != "" {
		err := m.printCode(ctx, code)
		if err == nil {
			log.Info("ENROLMENT CODE PRINTED", "printer", m.opt.Printer)
			return
		}
		log.Warn("could not print the enrolment code", "printer", m.opt.Printer, "err", err)
	}
	log.Info("ENROLMENT CODE", "code", code)
}

func (m *Marshal) printCode(ctx context.Context, code string) error {
	ask := func(noun string, args ...string) error {
		ctx, cancel := context.WithTimeout(ctx, printTimeout)
		defer cancel()
		_, err := m.c.RequestDialect(ctx, monolink.V2, m.opt.Printer, "PRINT", noun, args...)
		return err
	}
	// A blank line is a space: ukaz refuses an empty PRINT:TEXT.
	for _, line := range []string{
		"MARSHAL - enrolment",
		" ",
		"    " + code,
		" ",
		"Enter this code at monoview to become",
		"the first person in the bubble.",
		"It works once.",
	} {
		if err := ask("TEXT", line); err != nil {
			return err
		}
	}
	// As ukaz ends its own cards: the cutter sits above the print head, so
	// the last lines are advanced past it first, or the cut lands in them.
	// 8 is ukaz's CONFIG_PRINTER_FEED_BEFORE_CUT, found on the hardware.
	if err := ask("FEED", "8"); err != nil {
		return err
	}
	return ask("CUT", "FULL")
}

// ─── requests ────────────────────────────────────────────────────────

// arity is every request marshal serves, and the fewest and most arguments
// it takes.
var arity = map[string][2]int{
	"AUTH:CHALLENGE": {0, 0},
	"AUTH:PASSKEY":   {5, 16}, // nonce, credential, authenticator data, signature, client data…
	"AUTH:KEY":       {4, 4},  // nonce, name, credential, signature
	"AUTH:ENROL":     {6, 7},  // code, name, kind, id, alg, key[, label]
	"AUTH:REDEEM":    {6, 7},  // code, name, kind, id, alg, key[, label]
	"SET:SESSION":    {1, 1},  // token
	"STOP:SESSION":   {1, 1},  // token
	"GET:SESSIONS":   {0, 0},
	"STOP:SESSIONS":  {1, 1}, // name: every session, invitation and ticket of theirs
	"GET:ALLOW":      {2, 2}, // token, action
	"GET:TICKET":     {1, 1}, // token
	"GET:USERS":      {0, 0},
	"NEW:INVITE":     {1, 1}, // name
	"GET:KEYS":       {1, 1}, // name
	"STOP:KEY":       {2, 2}, // name, ref
	"STOP:USER":      {1, 1}, // name
	"SET:GRANT":      {2, 2}, // user, pattern
	"STOP:GRANT":     {2, 2}, // user, pattern
	"GET:GRANTS":     {1, 1}, // user
}

// Cmd serves every request to marshal that its object model does not:
// signing in, sessions, people and grants.
//
// Arguments are never logged. Between them they carry codes, signatures
// and session tokens.
func (m *Marshal) Cmd(req *monolink.Request) {
	msg := req.Msg
	if to, err := monolink.ParseAddress(msg.To); err != nil || to.Node != NodeName || to.Bubble != "" {
		return
	}
	switch msg.Verb {
	case monolink.VerbOK, monolink.VerbErr, monolink.VerbPong, monolink.VerbPub, monolink.VerbReg, monolink.VerbFire:
		return
	}
	if msg.Version != monolink.V2 {
		// A v1 panel can still see marshal is alive; everything else needs
		// v2, whose escaping names and records rely on.
		if msg.Verb == monolink.VerbPing {
			req.Reply(monolink.VerbPong, monolink.VerbPong)
			return
		}
		req.Reply(monolink.VerbErr, monolink.CodeVerb)
		return
	}

	noun, args, err := m.serve(msg)
	m.publish()
	if err != nil {
		var re *monolink.ReplyError
		if !errors.As(err, &re) {
			re = &monolink.ReplyError{Code: monolink.CodeInternal, Detail: err.Error()}
		}
		log.Info("REFUSED", "from", msg.From, "verb", msg.Verb, "noun", msg.Noun, "code", re.Code, "why", re.Detail)
		if re.Detail == "" {
			req.Reply(monolink.VerbErr, re.Code)
		} else {
			req.Reply(monolink.VerbErr, re.Code, re.Detail)
		}
		return
	}
	log.Debug("SERVED", "from", msg.From, "verb", msg.Verb, "noun", msg.Noun)
	if err := req.Reply(monolink.VerbOK, noun, args...); err != nil {
		// An answer that does not fit a frame is not sent at all: say so,
		// rather than leave the asker to time out.
		log.Error("ANSWER DOES NOT FIT", "from", msg.From, "verb", msg.Verb, "noun", msg.Noun, "err", err)
		req.Reply(monolink.VerbErr, monolink.CodeState, "the answer does not fit in one frame")
	}
}

func (m *Marshal) serve(msg monolink.Message) (string, []string, error) {
	key := msg.Verb + ":" + msg.Noun
	n, ok := arity[key]
	if !ok {
		for k := range arity {
			if strings.HasPrefix(k, msg.Verb+":") {
				return "", nil, monolink.Fail(monolink.CodeNoun, "")
			}
		}
		return "", nil, monolink.Fail(monolink.CodeVerb, "")
	}
	a := msg.Args
	if len(a) < n[0] || len(a) > n[1] {
		takes := strconv.Itoa(n[0])
		if n[1] != n[0] {
			takes += " to " + strconv.Itoa(n[1])
		}
		return "", nil, monolink.Fail(monolink.CodeArgc, key+" takes "+takes)
	}
	from, err := monolink.ParseAddress(msg.From)
	if err != nil {
		return "", nil, monolink.Fail(monolink.CodeArg, "unreadable sender")
	}
	// The hub refuses another bubble's senders; marshal does too, rather than
	// take one for its own panel of the same name.
	if from.Bubble != "" {
		return "", nil, monolink.Fail(monolink.CodeDenied, "another bubble's people are not this one's")
	}
	panel := from.Node

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.expire(now)

	switch key {
	case "AUTH:CHALLENGE":
		return m.challenge(panel, now)
	case "AUTH:PASSKEY":
		return m.passkey(panel, a, now)
	case "AUTH:KEY":
		return m.panelKey(panel, a[0], a[1], a[2], a[3], now)
	case "AUTH:ENROL":
		return m.enrol(panel, a[0], a[1], a[2:], now)
	case "AUTH:REDEEM":
		return m.redeem(panel, a[0], a[1], a[2:], now)
	case "SET:SESSION":
		return m.keepAlive(panel, a[0], now)
	case "STOP:SESSION":
		return m.endSession(panel, a[0], now)
	case "GET:ALLOW":
		return m.allow(panel, a[0], a[1], now)
	case "GET:TICKET":
		return m.ticket(panel, a[0], now)
	}

	// The rest administer people, and are themselves actions: MARSHAL.*.
	// A person may also look after their own keys and read their own grants.
	who, ok := m.actor(from, now)
	if !ok {
		return "", nil, monolink.Fail(monolink.CodeDenied, "sign in first")
	}
	switch key {
	case "GET:GRANTS", "GET:KEYS", "STOP:KEY", "STOP:SESSIONS":
		if a[0] != who {
			if err := m.permit(who, msg.Verb, msg.Noun); err != nil {
				return "", nil, err
			}
		}
	case "NEW:INVITE":
		if err := m.mayInvite(who, a[0]); err != nil {
			return "", nil, err
		}
		// A new key must not come of a session someone left open, or took:
		// that would outlive every sign-out.
		if !m.fresh(from, now) {
			return "", nil, monolink.Fail(monolink.CodeDenied, "sign in again first: a new key needs a sign-in within five minutes")
		}
	default:
		if err := m.permit(who, msg.Verb, msg.Noun); err != nil {
			return "", nil, err
		}
	}
	// Nobody changes someone who may do more than they may, nor hands on
	// more than they hold: MARSHAL.SET.GRANT is not a way to become *.
	switch key {
	case "STOP:KEY", "STOP:USER", "SET:GRANT", "STOP:GRANT", "STOP:SESSIONS":
		if t := m.st.Users[a[0]]; t != nil && a[0] != who && !m.coversAll(who, t.Grants) {
			return "", nil, monolink.Fail(monolink.CodeDenied, a[0]+" may do more than you")
		}
	}
	switch key {
	case "SET:GRANT", "STOP:GRANT":
		if !covers(m.st.Users[who].Grants, a[1]) {
			return "", nil, monolink.Fail(monolink.CodeDenied, "only what your own grants cover")
		}
	}
	switch key {
	case "GET:SESSIONS":
		return m.listSessions()
	case "STOP:SESSIONS":
		return m.stopEverything(a[0])
	case "GET:USERS":
		return m.listUsers()
	case "NEW:INVITE":
		return m.invite(who, a[0], now)
	case "GET:KEYS":
		return m.listKeys(a[0])
	case "STOP:KEY":
		return m.stopKey(a[0], a[1])
	case "STOP:USER":
		return m.stopUser(a[0])
	case "SET:GRANT":
		return m.setGrant(a[0], a[1])
	case "STOP:GRANT":
		return m.stopGrant(a[0], a[1])
	default: // GET:GRANTS
		return m.getGrants(a[0])
	}
}

// ─── signing in ──────────────────────────────────────────────────────

// challenge is something for a panel to have signed: 32 random bytes,
// base64url — as a passkey's client data carries its challenge — good for a
// minute and one answer, from that panel only.
func (m *Marshal) challenge(panel string, now time.Time) (string, []string, error) {
	out := 0
	for n, ch := range m.challenges {
		switch {
		case now.After(ch.expires):
			delete(m.challenges, n)
		case ch.panel == panel:
			out++
		}
	}
	if out >= maxChallenges {
		return "", nil, monolink.Fail(monolink.CodeBusy, "too many sign-ins at once")
	}
	nonce := randB64(32)
	m.challenges[nonce] = challenge{panel: panel, expires: now.Add(challengeTTL)}
	return auth.NounChallenge, []string{nonce}, nil
}

// answered takes a challenge up: it must be this panel's, and live. Right
// or wrong, it is gone.
func (m *Marshal) answered(panel, nonce string, now time.Time) bool {
	ch, ok := m.challenges[nonce]
	delete(m.challenges, nonce)
	return ok && ch.panel == panel && !now.After(ch.expires)
}

// findKey is the person and key a credential id belongs to.
func (m *Marshal) findKey(id string) (string, *Key) {
	for name, u := range m.st.Users {
		for _, k := range u.Keys {
			if k.ID == id {
				return name, k
			}
		}
	}
	return "", nil
}

// passkey signs in whoever's passkey answered the challenge. The person is
// not named: the passkey says who it is.
func (m *Marshal) passkey(panel string, args []string, now time.Time) (string, []string, error) {
	nonce, a, err := auth.ParsePasskeyArgs(args)
	if err != nil {
		return "", nil, monolink.Fail(monolink.CodeArg, err.Error())
	}
	if !m.answered(panel, nonce, now) {
		return "", nil, monolink.Fail(monolink.CodeDenied, "no such challenge")
	}
	if m.opt.Site.ID == "" {
		return "", nil, monolink.Fail(monolink.CodeState, "marshal is not set up for passkeys")
	}
	name, k := m.findKey(a.CredentialID)
	if k == nil || k.Kind != auth.KindWebAuthn {
		return "", nil, monolink.Fail(monolink.CodeDenied, "")
	}
	count, err := m.opt.Site.VerifyAssertion(k.Credential, nonce, a)
	if err != nil {
		log.Warn("PASSKEY REFUSED", "user", name, "key", k.Ref, "why", err)
		return "", nil, monolink.Fail(monolink.CodeDenied, "")
	}
	// The counter moves on only if the sign-in is saved: a failed one leaves
	// memory as the file is.
	snap := m.snapshot()
	k.Count = count
	noun, out, err := m.openSession(name, panel, k.Ref, now)
	if err != nil {
		m.st = snap
		return "", nil, err
	}
	return noun, out, nil
}

// panelKey signs name in with a panel's own key.
func (m *Marshal) panelKey(panel, nonce, name, id, sig string, now time.Time) (string, []string, error) {
	if !m.answered(panel, nonce, now) {
		return "", nil, monolink.Fail(monolink.CodeDenied, "no such challenge")
	}
	owner, k := m.findKey(id)
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if k == nil || owner != name || err != nil || auth.VerifyKey(k.Credential, name, panel, nonce, raw) != nil {
		return "", nil, monolink.Fail(monolink.CodeDenied, "")
	}
	return m.openSession(name, panel, k.Ref, now)
}

// enrol makes the first person, by the code marshal printed: their key,
// and every grant. It is open only while nobody can sign in.
func (m *Marshal) enrol(panel, code, name string, cred []string, now time.Time) (string, []string, error) {
	if m.enrolCode == "" {
		return "", nil, monolink.Fail(monolink.CodeState, "enrolment is closed")
	}
	if subtle.ConstantTimeCompare([]byte(normaliseCode(code)), []byte(normaliseCode(m.enrolCode))) != 1 {
		return "", nil, m.wrongCode(panel, now)
	}
	if slices.Contains(m.st.Retired, name) {
		return "", nil, monolink.Fail(monolink.CodeState, "that name was someone's, and is not given again")
	}
	if err := m.roomFor(name); err != nil {
		return "", nil, err
	}
	c, err := m.newKey(name, cred)
	if err != nil {
		return "", nil, err
	}
	snap := m.snapshot()
	u := m.st.Users[name]
	if u == nil {
		u = &User{Grants: []string{}, Created: now}
		m.st.Users[name] = u
	}
	if !slices.Contains(u.Grants, "*") {
		u.Grants = append(u.Grants, "*")
	}
	k := &Key{Credential: c, Ref: c.Ref(), Added: now}
	u.Keys = append(u.Keys, k)
	noun, args, err := m.openSession(name, panel, k.Ref, now)
	if err != nil {
		m.st = snap // enrolment stays open: nobody was made
		return "", nil, err
	}
	m.enrolCode = ""
	m.codes = map[string]*lockout{}
	log.Info("ENROLLED", "user", name, "panel", panel, "key", k.Ref)
	return noun, args, nil
}

// newKey checks a credential offered for name: a person's name, a key
// marshal can keep, and nobody's already.
func (m *Marshal) newKey(name string, args []string) (auth.Credential, error) {
	if !auth.ValidName(name) {
		return auth.Credential{}, monolink.Fail(monolink.CodeArg, "not a name")
	}
	c, err := auth.ParseCredential(args)
	if err != nil {
		return auth.Credential{}, monolink.Fail(monolink.CodeArg, err.Error())
	}
	pub, err := c.PublicKey()
	if err != nil {
		return auth.Credential{}, monolink.Fail(monolink.CodeArg, err.Error())
	}
	// A panel key's id is its own fingerprint, so one key cannot be offered
	// again under another id.
	if raw, ok := pub.(ed25519.PublicKey); ok && c.Kind == auth.KindEd25519 {
		id := sha256.Sum256(raw)
		if c.ID != base64.RawURLEncoding.EncodeToString(id[:]) {
			return auth.Credential{}, monolink.Fail(monolink.CodeArg, "an ed25519 key's id is its own fingerprint")
		}
	}
	if m.keyTaken(c) {
		return auth.Credential{}, monolink.Fail(monolink.CodeState, "that key is already someone's")
	}
	if u := m.st.Users[name]; u != nil && len(u.Keys) >= maxKeys {
		return auth.Credential{}, monolink.Fail(monolink.CodeState, "as many keys as a person may have")
	}
	return c, nil
}

// mayInvite says whether who may make an invitation by which name adds a
// key. Oneself, for another device, always. Someone new needs NEW.INVITE. A
// key for someone else who exists makes the inviter able to become them: it
// needs SET.KEY, and every grant they hold. It is asked again when the
// invitation is taken up, since the inviter may have lost the grant by then.
func (m *Marshal) mayInvite(who, name string) error {
	target, exists := m.st.Users[name]
	switch {
	case name == who:
		return nil
	case !exists:
		return m.permit(who, monolink.VerbNew, auth.NounInvite)
	}
	if err := m.permit(who, monolink.VerbSet, auth.NounKey); err != nil {
		return err
	}
	if !m.coversAll(who, target.Grants) {
		return monolink.Fail(monolink.CodeDenied, name+" may do more than you")
	}
	return nil
}

// invite makes a one-time code by which name adds a key: someone new, who
// then exists with no grants, or another device of someone who does.
func (m *Marshal) invite(by, name string, now time.Time) (string, []string, error) {
	if !auth.ValidName(name) {
		return "", nil, monolink.Fail(monolink.CodeArg, "not a name")
	}
	if slices.Contains(m.st.Retired, name) {
		return "", nil, monolink.Fail(monolink.CodeState, "that name was someone's, and is not given again")
	}
	if err := m.roomFor(name); err != nil {
		return "", nil, err
	}
	// A newer invitation for the same name from the same person replaces the
	// older: its code stops working. And each inviter has a few at most, so
	// nobody — a person with no grants inviting themselves — can take every
	// place and leave none for anyone else.
	mine := 0
	for h, iv := range m.invites {
		switch {
		case now.After(iv.expires), iv.by == by && iv.name == name:
			delete(m.invites, h)
		case iv.by == by:
			mine++
		}
	}
	if mine >= maxInvitesEach {
		return "", nil, monolink.Fail(monolink.CodeBusy, "as many invitations out as one person may have")
	}
	if len(m.invites) >= maxInvites {
		return "", nil, monolink.Fail(monolink.CodeBusy, "too many invitations out")
	}
	code, err := newCode()
	if err != nil {
		return "", nil, err
	}
	_, exists := m.st.Users[name]
	iv := invite{name: name, by: by, byGen: m.st.Users[by].Gen, fresh: !exists, expires: now.Add(inviteTTL)}
	m.invites[hashCode(code)] = iv
	log.Info("INVITED", "user", name, "by", by)
	return auth.NounInvite, []string{code, iv.expires.Format(time.RFC3339)}, nil
}

// redeem takes an invitation up: the code must be for name, and the key
// becomes theirs — if the invitation may still do what it was made for.
func (m *Marshal) redeem(panel, code, name string, cred []string, now time.Time) (string, []string, error) {
	guesses := panel + "/" + name
	h := hashCode(code)
	iv, ok := m.invites[h]
	if !ok || iv.name != name || now.After(iv.expires) {
		return "", nil, m.wrongCode(guesses, now)
	}
	// An invitation for someone new is not a key for whoever has taken the
	// name since; an inviter who has lost the right to make it has lost the
	// right to have it used; and one made while a key since removed was
	// trusted goes with that key — a stolen key's self-invitation must not
	// outlive its removal.
	_, exists := m.st.Users[name]
	var void error
	switch {
	case m.st.Users[iv.by] == nil || m.st.Users[iv.by].Gen != iv.byGen:
		void = monolink.Fail(monolink.CodeState, "a key of its inviter's has been removed since")
	case iv.fresh && exists:
		void = monolink.Fail(monolink.CodeState, "that name has become someone's since")
	case !iv.fresh && !exists:
		void = monolink.Fail(monolink.CodeState, "no such person any more")
	default:
		void = m.mayInvite(iv.by, name)
	}
	if void != nil {
		delete(m.invites, h)
		log.Warn("INVITATION VOID", "user", name, "by", iv.by, "why", void)
		return "", nil, void
	}
	if err := m.roomFor(name); err != nil {
		return "", nil, err
	}
	c, err := m.newKey(name, cred)
	if err != nil {
		return "", nil, err
	}
	snap := m.snapshot()
	u := m.st.Users[name]
	if u == nil {
		u = &User{Grants: []string{}, Created: now}
		m.st.Users[name] = u
	}
	k := &Key{Credential: c, Ref: c.Ref(), Added: now}
	u.Keys = append(u.Keys, k)
	// Someone who existed may do more on their new device than the ticket
	// on their old one says — nothing, but tickets are cheap to renew.
	noun, args, err := m.openSession(name, panel, k.Ref, now)
	if err != nil {
		m.st = snap
		return "", nil, err
	}
	delete(m.invites, h)
	delete(m.codes, guesses)
	log.Info("KEY ADDED", "user", name, "panel", panel, "key", k.Ref, "invited_by", iv.by)
	return noun, args, nil
}

// ─── sessions ────────────────────────────────────────────────────────

func (m *Marshal) openSession(user, panel, key string, now time.Time) (string, []string, error) {
	snap := m.snapshot()
	// A panel signing in over and over — a fault, or a panel taken over —
	// ends its person's oldest sessions, not marshal's patience.
	var mine []string
	for h, s := range m.st.Sessions {
		if s.User == user {
			mine = append(mine, h)
		}
	}
	if len(mine) >= maxSessions {
		sort.Slice(mine, func(i, j int) bool { return m.st.Sessions[mine[i]].Since.Before(m.st.Sessions[mine[j]].Since) })
		for _, h := range mine[:len(mine)-maxSessions+1] {
			delete(m.st.Sessions, h)
		}
		// An evicted session's tickets must not outlive it; the hub cannot
		// tell one session's tickets from another's, so the person's others
		// go too, and their panels ask for new ones.
		m.endTickets(user)
	}
	token := randHex(32)
	s := &Session{User: user, Panel: panel, Key: key, Since: now}
	m.extend(s, now)
	m.st.Sessions[hashToken(token)] = s
	if err := m.save(); err != nil {
		m.st = snap
		return "", nil, err
	}
	m.kick()
	log.Info("SIGNED IN", "user", user, "panel", panel, "key", key)
	return auth.NounSession, sessionArgs(token, s.User, s.Expires), nil
}

func sessionArgs(token, user string, expires time.Time) []string {
	return []string{token, user, expires.Format(time.RFC3339)}
}

// session finds a live session by its token. It must be asked about by
// the panel that holds it: a session belongs to one panel (SPEC §24).
func (m *Marshal) session(panel, token string, now time.Time) (*Session, string, error) {
	h := hashToken(token)
	s, ok := m.st.Sessions[h]
	if !ok || s.Panel != panel || !now.Before(s.Expires) {
		return nil, h, monolink.Fail(monolink.CodeNAC, "no such session")
	}
	return s, h, nil
}

// extend keeps s open for another TTL, but never past maxSessionAge from its
// sign-in: a stolen token, renewed faithfully, still dies.
func (m *Marshal) extend(s *Session, now time.Time) {
	s.Expires = now.Add(m.opt.TTL)
	if limit := s.Since.Add(maxSessionAge); s.Expires.After(limit) {
		s.Expires = limit
	}
}

func (m *Marshal) keepAlive(panel, token string, now time.Time) (string, []string, error) {
	s, _, err := m.session(panel, token, now)
	if err != nil {
		return "", nil, err
	}
	old := s.Expires
	m.extend(s, now)
	if err := m.save(); err != nil {
		s.Expires = old
		return "", nil, err
	}
	return auth.NounSession, sessionArgs(token, s.User, s.Expires), nil
}

// endSession signs a person out at a panel, and ends the tickets that
// session was renewing — and, since the hub cannot tell one session's
// tickets from another's, the person's others too, whose panels simply ask
// for new ones.
func (m *Marshal) endSession(panel, token string, now time.Time) (string, []string, error) {
	s, h, err := m.session(panel, token, now)
	if err != nil {
		return "", nil, err
	}
	snap := m.snapshot()
	delete(m.st.Sessions, h)
	m.endTickets(s.User)
	if err := m.save(); err != nil {
		m.st = snap
		return "", nil, err
	}
	m.kick()
	log.Info("SIGNED OUT", "user", s.User, "panel", panel)
	return auth.NounSession, sessionArgs(token, s.User, now), nil
}

func (m *Marshal) allow(panel, token, action string, now time.Time) (string, []string, error) {
	s, _, err := m.session(panel, token, now)
	if err != nil {
		return "", nil, err
	}
	if u := m.st.Users[s.User]; u != nil && auth.Allowed(u.Grants, action) {
		return auth.NounAllow, []string{"YES"}, nil
	}
	return auth.NounAllow, []string{"NO", "no grant covers " + action}, nil
}

// ticket signs a ticket for the session token holds — which must be this
// panel's — naming the person, the panel and their grants, for TicketTTL or
// the rest of the session if that is shorter. The panel shows it to the hub,
// which holds the connection to those grants (SECURITY.txt §5).
//
// Asking for one is using the session, and keeps it open: a panel renews its
// ticket every few minutes while it is connected, and a session nobody
// renews ends within TTL.
func (m *Marshal) ticket(panel, token string, now time.Time) (string, []string, error) {
	if m.opt.TicketKey == nil {
		return "", nil, monolink.Fail(monolink.CodeState, "marshal has no key to sign tickets with")
	}
	s, _, err := m.session(panel, token, now)
	if err != nil {
		return "", nil, err
	}
	u := m.st.Users[s.User]
	if u == nil {
		return "", nil, monolink.Fail(monolink.CodeNAC, "no such session")
	}
	if len(u.Grants) > auth.MaxTicketGrants {
		return "", nil, monolink.Fail(monolink.CodeState, "more grants than a ticket holds")
	}
	old := s.Expires
	m.extend(s, now)
	if err := m.save(); err != nil {
		s.Expires = old
		return "", nil, err
	}
	expires := now.Add(auth.TicketTTL)
	if s.Expires.Before(expires) {
		expires = s.Expires
	}
	// Signed after the person's tickets were last ended, even within the
	// same millisecond: the hub takes none issued up to then.
	issued := now.Truncate(time.Millisecond)
	if cut := m.ended[s.User]; !issued.After(cut) {
		issued = cut.Add(time.Millisecond)
	}
	if issued.After(m.lastIssued[s.User]) {
		m.lastIssued[s.User] = issued
	}
	t := auth.Ticket{Person: s.User, Panel: panel, Issued: issued, Expires: expires, Grants: u.Grants}.Sign(m.opt.TicketKey)
	return auth.NounTicket, t.Args(), nil
}

// endTickets voids every ticket signed for name until now: what they may
// do, or whether they exist at all, has changed, and a ticket signed before
// cannot know it. The hub drops the connections holding one and refuses any
// shown again; their panels ask for a new ticket, signed after.
//
// It is called with m.mu held, before the change is saved: the cutoff is
// saved with it (State.Ending), and deliverEndings tells the hub — again
// after a reconnect or a restart — until the hub has acknowledged it or every
// ticket it covers has expired. Call kick once the change is saved.
func (m *Marshal) endTickets(name string) {
	since := m.now().Truncate(time.Millisecond)
	// Every ticket signed until now: one signed a moment ago can carry a time
	// a millisecond ahead of the clock (see ticket).
	if last := m.lastIssued[name]; last.After(since) {
		since = last
	}
	if since.After(m.ended[name]) {
		m.ended[name] = since
	}
	if since.After(m.st.Ending[name]) {
		m.st.Ending[name] = since
	}
}

// kick wakes deliverEndings.
func (m *Marshal) kick() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// deliverEndings tells the hub the cutoffs it has not acknowledged, whenever
// one is made, on every connect, and every few seconds while any is left.
func (m *Marshal) deliverEndings(ctx context.Context) {
	t := time.NewTicker(deliverEvery)
	defer t.Stop()
	for {
		m.sendEndings(ctx)
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		case <-t.C:
		}
	}
}

func (m *Marshal) sendEndings(ctx context.Context) {
	m.mu.Lock()
	now := m.now()
	pending := map[string]time.Time{}
	lapsed := false
	for p, since := range m.st.Ending {
		if now.Sub(since) > auth.TicketTTL+auth.ClockSkew {
			delete(m.st.Ending, p) // every ticket it covers has expired by itself
			lapsed = true
			continue
		}
		pending[p] = since
	}
	if lapsed {
		m.save()
	}
	m.mu.Unlock()

	for p, since := range pending {
		ask, cancel := context.WithTimeout(ctx, printTimeout)
		_, err := m.c.RequestDialect(ask, monolink.V2, auth.Hub, monolink.VerbStop, auth.NounTickets, p, auth.TimeArg(since))
		cancel()
		var re *monolink.ReplyError
		switch {
		case err == nil:
			log.Info("TICKETS ENDED", "user", p)
		case errors.As(err, &re):
			// The hub said no: asking again would change nothing.
			log.Error("TICKETS NOT ENDED: the hub refused", "user", p, "err", err)
		default:
			log.Warn("tickets not ended yet; asking again", "user", p, "err", err)
			continue
		}
		m.mu.Lock()
		if m.st.Ending[p].Equal(since) {
			delete(m.st.Ending, p)
			m.save()
		}
		m.mu.Unlock()
	}
	m.publish()
}

func (m *Marshal) listSessions() (string, []string, error) {
	live := make([]*Session, 0, len(m.st.Sessions))
	for _, s := range m.st.Sessions {
		live = append(live, s)
	}
	sort.Slice(live, func(i, j int) bool { return live[i].Since.Before(live[j].Since) })
	// One frame carries sixteen: the newest, oldest first.
	if len(live) > monolink.MaxArgs {
		live = live[len(live)-monolink.MaxArgs:]
	}
	out := make([]string, len(live))
	for i, s := range live {
		out[i] = monolink.Record(s.User, s.Panel, s.Since.Format(time.RFC3339))
	}
	return auth.NounSessions, out, nil
}

// expire forgets sessions whose time is up, and reports whether it did.
func (m *Marshal) expire(now time.Time) bool {
	gone := false
	for h, s := range m.st.Sessions {
		if !now.Before(s.Expires) {
			delete(m.st.Sessions, h)
			gone = true
		}
	}
	return gone
}

// endSessions ends name's sessions — only those opened with key, if one is
// given — and returns them, for putting back should saving fail.
func (m *Marshal) endSessions(name, key string) map[string]*Session {
	ended := map[string]*Session{}
	for h, s := range m.st.Sessions {
		if s.User == name && (key == "" || s.Key == key) {
			ended[h] = s
			delete(m.st.Sessions, h)
		}
	}
	return ended
}

// actor is the person a request speaks for: the actor in its address,
// provided that panel holds a live session for them.
func (m *Marshal) actor(from monolink.Address, now time.Time) (string, bool) {
	if from.Actor == "" {
		return "", false
	}
	for _, s := range m.st.Sessions {
		if s.User == from.Actor && s.Panel == from.Node && now.Before(s.Expires) {
			return s.User, true
		}
	}
	return "", false
}

// fresh reports whether the person from speaks for signed in at that panel
// within freshSignIn.
func (m *Marshal) fresh(from monolink.Address, now time.Time) bool {
	for _, s := range m.st.Sessions {
		if s.User == from.Actor && s.Panel == from.Node && now.Before(s.Expires) && now.Sub(s.Since) <= freshSignIn {
			return true
		}
	}
	return false
}

// permit lets who do MARSHAL.<verb>.<noun> if a grant of theirs covers it.
func (m *Marshal) permit(who, verb, noun string) error {
	action := auth.Action(NodeName, verb, noun)
	if u := m.st.Users[who]; u == nil || !auth.Allowed(u.Grants, action) {
		return monolink.Fail(monolink.CodeDenied, "needs "+action)
	}
	return nil
}

// covers reports whether grants reach at least as far as pattern does.
func covers(grants []string, pattern string) bool {
	want, _ := strings.CutSuffix(pattern, "*")
	for _, g := range grants {
		if g == pattern {
			return true
		}
		if prefix, ok := strings.CutSuffix(g, "*"); ok && strings.HasPrefix(want, prefix) {
			return true
		}
	}
	return false
}

// coversAll reports whether who may do everything grants allow.
func (m *Marshal) coversAll(who string, grants []string) bool {
	u := m.st.Users[who]
	if u == nil {
		return false
	}
	for _, g := range grants {
		if !covers(u.Grants, g) {
			return false
		}
	}
	return true
}

// ─── people, keys and grants ─────────────────────────────────────────

func (m *Marshal) user(name string) (*User, error) {
	if !auth.ValidName(name) {
		return nil, monolink.Fail(monolink.CodeArg, "not a name")
	}
	u, ok := m.st.Users[name]
	if !ok {
		return nil, monolink.Fail(monolink.CodeNAC, "no such person")
	}
	return u, nil
}

func (m *Marshal) listUsers() (string, []string, error) {
	names := make([]string, 0, len(m.st.Users))
	for n := range m.st.Users {
		names = append(names, n)
	}
	sort.Strings(names)
	return auth.NounUsers, names, nil
}

func (m *Marshal) listKeys(name string) (string, []string, error) {
	u, err := m.user(name)
	if err != nil {
		return "", nil, err
	}
	out := make([]string, len(u.Keys))
	for i, k := range u.Keys {
		out[i] = monolink.Record(k.Ref, k.Kind, k.Label, k.Added.Format(time.RFC3339))
	}
	return auth.NounKeys, out, nil
}

// stopKey removes one of name's keys and ends the sessions it opened. The
// last key stays: without it, nobody could sign in as them again.
func (m *Marshal) stopKey(name, ref string) (string, []string, error) {
	u, err := m.user(name)
	if err != nil {
		return "", nil, err
	}
	i := slices.IndexFunc(u.Keys, func(k *Key) bool { return k.Ref == ref })
	if i < 0 {
		return "", nil, monolink.Fail(monolink.CodeNAC, "no such key")
	}
	if len(u.Keys) == 1 {
		return "", nil, monolink.Fail(monolink.CodeState, "the last key stays")
	}
	snap := m.snapshot()
	u.Keys = slices.Delete(slices.Clone(u.Keys), i, i+1)
	// Whatever the key could still bring about goes with it: the sessions it
	// opened, every ticket of theirs, and the invitations they made while it
	// was trusted — a self-invitation made with a stolen key would otherwise
	// let the thief back in after its removal.
	u.Gen++
	ended := m.endSessions(name, ref)
	m.endTickets(name)
	if err := m.save(); err != nil {
		m.st = snap
		return "", nil, err
	}
	m.kick()
	log.Info("KEY REMOVED", "user", name, "key", ref, "sessions_ended", len(ended))
	return auth.NounKey, []string{name, ref}, nil
}

// stopEverything ends every session of name's, every invitation for them or
// by them, and every ticket: what an owner does on finding a session taken,
// or a device gone, when they hold no token for it. Their keys stay; a key
// known to be lost is removed with STOP:KEY.
func (m *Marshal) stopEverything(name string) (string, []string, error) {
	u, err := m.user(name)
	if err != nil {
		return "", nil, err
	}
	snap := m.snapshot()
	u.Gen++
	ended := m.endSessions(name, "")
	m.endTickets(name)
	if err := m.save(); err != nil {
		m.st = snap
		return "", nil, err
	}
	m.kick()
	voided := 0
	for h, iv := range m.invites {
		if iv.name == name || iv.by == name {
			delete(m.invites, h)
			voided++
		}
	}
	log.Info("SIGNED OUT EVERYWHERE", "user", name, "sessions", len(ended), "invitations", voided)
	return auth.NounSessions, []string{name, strconv.Itoa(len(ended))}, nil
}

func (m *Marshal) stopUser(name string) (string, []string, error) {
	u, err := m.user(name)
	if err != nil {
		return "", nil, err
	}
	if slices.Contains(u.Grants, "*") && len(u.Keys) > 0 && m.holdersOfAll() == 1 {
		return "", nil, monolink.Fail(monolink.CodeState, "the last person holding * stays")
	}
	snap := m.snapshot()
	delete(m.st.Users, name)
	m.endSessions(name, "")
	m.st.Retired = append(m.st.Retired, name)
	m.endTickets(name)
	if err := m.save(); err != nil {
		m.st = snap
		return "", nil, err
	}
	m.kick()
	// Invitations for them, and by them: whoever they invited is let in by
	// nobody now.
	for h, iv := range m.invites {
		if iv.name == name || iv.by == name {
			delete(m.invites, h)
		}
	}
	log.Info("REMOVED USER", "user", name)
	return auth.NounUser, []string{name}, nil
}

func (m *Marshal) setGrant(name, pattern string) (string, []string, error) {
	u, err := m.user(name)
	if err != nil {
		return "", nil, err
	}
	if !auth.ValidPattern(pattern) {
		return "", nil, monolink.Fail(monolink.CodeArg, "not a grant")
	}
	if !slices.Contains(u.Grants, pattern) {
		// A ticket carries every grant, and a frame carries a ticket: one
		// grant more than it holds and the person could get no ticket at all.
		if len(u.Grants) >= auth.MaxTicketGrants {
			return "", nil, monolink.Fail(monolink.CodeState, "as many grants as a ticket holds ("+strconv.Itoa(auth.MaxTicketGrants)+"); a wider one covers several")
		}
		snap := m.snapshot()
		u.Grants = append(u.Grants, pattern)
		m.endTickets(name)
		if err := m.save(); err != nil {
			m.st = snap
			return "", nil, err
		}
		m.kick()
		log.Info("GRANTED", "user", name, "pattern", pattern)
	}
	return auth.NounGrant, []string{name}, nil
}

func (m *Marshal) stopGrant(name, pattern string) (string, []string, error) {
	u, err := m.user(name)
	if err != nil {
		return "", nil, err
	}
	i := slices.Index(u.Grants, pattern)
	if i < 0 {
		return "", nil, monolink.Fail(monolink.CodeNAC, "no such grant")
	}
	if pattern == "*" && len(u.Keys) > 0 && m.holdersOfAll() == 1 {
		return "", nil, monolink.Fail(monolink.CodeState, "the last person holding * keeps it")
	}
	snap := m.snapshot()
	u.Grants = slices.Delete(slices.Clone(u.Grants), i, i+1)
	m.endTickets(name)
	if err := m.save(); err != nil {
		m.st = snap
		return "", nil, err
	}
	m.kick()
	log.Info("REVOKED", "user", name, "pattern", pattern)
	return auth.NounGrant, []string{name}, nil
}

func (m *Marshal) getGrants(name string) (string, []string, error) {
	u, err := m.user(name)
	if err != nil {
		return "", nil, err
	}
	return auth.NounGrants, slices.Clone(u.Grants), nil
}

// holdersOfAll counts the people granted the whole bubble who can sign in —
// a person from before keys holds * on paper only. It must never reach zero,
// or nobody could administer anyone again.
func (m *Marshal) holdersOfAll() int {
	n := 0
	for _, u := range m.st.Users {
		if len(u.Keys) > 0 && slices.Contains(u.Grants, "*") {
			n++
		}
	}
	return n
}

// roomFor says whether name can be one more person: GET:USERS answers with
// every name in one frame, and PEOPLE carries them all in one field.
func (m *Marshal) roomFor(name string) error {
	if _, ok := m.st.Users[name]; ok {
		return nil
	}
	names := []string{name}
	for n := range m.st.Users {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > maxPeople || len(monolink.Escape(monolink.Record(names...))) > monolink.MaxField {
		return monolink.Fail(monolink.CodeState, "the bubble has as many people as it can list")
	}
	return nil
}

// keyTaken reports whether c's key is already someone's, by its id or by the
// public key itself.
func (m *Marshal) keyTaken(c auth.Credential) bool {
	der, err := base64.RawURLEncoding.DecodeString(c.Key)
	for _, u := range m.st.Users {
		for _, k := range u.Keys {
			if k.ID == c.ID {
				return true
			}
			if other, e := base64.RawURLEncoding.DecodeString(k.Key); err == nil && e == nil && bytes.Equal(der, other) {
				return true
			}
		}
	}
	return false
}

// ─── plumbing ────────────────────────────────────────────────────────

func (m *Marshal) save() error {
	if err := m.store.Save(m.st); err != nil {
		log.Error("SAVE FAILED", "err", err)
		return monolink.Fail(monolink.CodeInternal, "could not save")
	}
	return nil
}

// snapshot is a copy of the state, to put back should a change fail to
// save: what marshal answers must be what it keeps.
func (m *Marshal) snapshot() *State {
	b, err := json.Marshal(m.st)
	if err != nil {
		panic("marshal: state does not encode: " + err.Error())
	}
	st := &State{}
	if err := json.Unmarshal(b, st); err != nil {
		panic("marshal: state does not decode: " + err.Error())
	}
	if st.Ending == nil {
		st.Ending = map[string]time.Time{} // omitted when empty
	}
	return st
}

// publish sets marshal's properties; each is announced only if it changed.
// One publish at a time, the snapshot taken inside: two handlers finishing
// together cannot leave the older snapshot published.
func (m *Marshal) publish() {
	m.pubMu.Lock()
	defer m.pubMu.Unlock()
	m.mu.Lock()
	users, sessions, enrolling, ending := len(m.st.Users), len(m.st.Sessions), m.enrolCode != "", len(m.st.Ending)
	names := make([]string, 0, len(m.st.Users))
	for n := range m.st.Users {
		names = append(names, n)
	}
	m.mu.Unlock()
	sort.Strings(names)
	m.users.Set(strconv.Itoa(users))
	m.sessions.Set(strconv.Itoa(sessions))
	m.enrolling.Set(onOff(enrolling))
	m.ending.Set(strconv.Itoa(ending))
	if err := m.people.Set(monolink.Record(names...)); err != nil {
		log.Error("PEOPLE does not fit in one field", "people", len(names), "err", err)
	}
}

// onOff is a bool as the wire writes one (SPEC §19).
func onOff(b bool) string {
	if b {
		return "ON"
	}
	return "OFF"
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("marshal: no randomness: " + err.Error())
	}
	return b
}

func randHex(n int) string { return hex.EncodeToString(random(n)) }

func randB64(n int) string { return base64.RawURLEncoding.EncodeToString(random(n)) }
