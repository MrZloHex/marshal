// Package marshal is the bubble's people: who they are, which panel each is
// signed in at, and what they may do. SPEC.txt §24.
//
// It is policy, not a security boundary: a panel asks, marshal answers, the
// panel honours the answer. What marshal does guard is its own records — a
// request to change people must come from a panel holding a session for
// someone whose grants allow it.
package marshal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
	challengeTTL  = time.Minute // how long a challenge may be answered
	maxChallenges = 64          // outstanding at once, bubble-wide
	freeFailures  = 5           // wrong answers before a name is locked out
	baseLockout   = 30 * time.Second
	maxLockout    = 15 * time.Minute
	enrolSlot     = "" // the lockout slot for enrolment codes; never a name
	printTimeout  = 5 * time.Second
)

// Options configures a Marshal.
type Options struct {
	TTL     time.Duration // how long a session lasts unused
	Printer string        // node that prints the enrolment code; "" logs it
	Version string
}

type challenge struct {
	name, panel string
	expires     time.Time
}

type lockout struct {
	failures int
	until    time.Time
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
	enrolCode  string // set while the bubble has nobody in it
	challenges map[string]challenge
	lockouts   map[string]*lockout
}

// New loads the state and attaches marshal's object model to c. Register
// m.Cmd as c's "*" handler, then Connect, then Start.
func New(c *monolink.Client, store *Store, opt Options) (*Marshal, error) {
	st, err := store.Load()
	if err != nil {
		return nil, err
	}
	if opt.TTL <= 0 {
		opt.TTL = 30 * 24 * time.Hour
	}
	m := &Marshal{c: c, store: store, opt: opt, now: time.Now, st: st,
		challenges: map[string]challenge{}, lockouts: map[string]*lockout{}}

	// Not USERS or SESSIONS: those are nouns marshal answers with lists, and
	// a property of the same name would be served in their place.
	node := monolink.NewNode(c, monolink.NodeInfo{Class: monolink.ClassNode, Product: "marshal", Version: opt.Version})
	m.users = node.Prop("USERS.COUNT", monolink.Int(0, 1000), "people in the bubble")
	m.sessions = node.Prop("SESSIONS.COUNT", monolink.Int(0, 100000), "sessions open")
	m.enrolling = node.Prop("ENROLLING", monolink.Bool(), "nobody exists yet; an enrolment code is out")
	// Who is in the bubble, readable by any node — synapse must know whom a
	// message can go to. Names are no secret inside the household; what
	// each may do is, and GET:USERS stays behind MARSHAL.*.
	m.people = node.Prop("PEOPLE", monolink.Str(0), "the people of the bubble, a record of names")

	if len(st.Users) == 0 {
		if m.enrolCode, err = newEnrolCode(); err != nil {
			return nil, err
		}
	}
	m.publish()
	return m, nil
}

// Start runs what marshal does unasked: putting the enrolment code where
// the owner will find it, and forgetting expired sessions.
func (m *Marshal) Start(ctx context.Context) {
	if code := m.EnrolCode(); code != "" {
		go m.announceEnrolment(ctx, code)
	}
	go func() {
		t := time.NewTicker(time.Hour)
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

// EnrolCode is the code that creates the first person, or "" once there is
// one.
func (m *Marshal) EnrolCode() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enrolCode
}

// ─── the enrolment code ──────────────────────────────────────────────

// Crockford's base32: no I, L, O or U, so what is printed is what gets typed.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newEnrolCode is 60 random bits as XXXX-XXXX-XXXX. With the lockout, that
// is not guessable over a bus.
func newEnrolCode() (string, error) {
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
		"Enter this code at a panel to become",
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

// arity is every request marshal serves, and how many arguments it takes.
var arity = map[string]int{
	"AUTH:USER":    1, // name
	"AUTH:PROOF":   3, // name, nonce, proof
	"AUTH:ENROL":   4, // code, name, kdf, verifier
	"SET:SESSION":  1, // token
	"STOP:SESSION": 1, // token
	"GET:SESSIONS": 0,
	"GET:ALLOW":    2, // token, action
	"GET:USERS":    0,
	"NEW:USER":     3, // name, kdf, verifier
	"SET:USER":     3, // name, kdf, verifier
	"STOP:USER":    1, // name
	"SET:GRANT":    2, // user, pattern
	"STOP:GRANT":   2, // user, pattern
	"GET:GRANTS":   1, // user
}

// Cmd serves every request to marshal that its object model does not:
// signing in, sessions, people and grants.
//
// Arguments are never logged. Between them they carry verifiers, proofs
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
	req.Reply(monolink.VerbOK, noun, args...)
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
	if len(a) != n {
		return "", nil, monolink.Fail(monolink.CodeArgc, key+" takes "+strconv.Itoa(n))
	}
	from, err := monolink.ParseAddress(msg.From)
	if err != nil {
		return "", nil, monolink.Fail(monolink.CodeArg, "unreadable sender")
	}
	panel := from.Node

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.expire(now)

	switch key {
	case "AUTH:USER":
		return m.challenge(panel, a[0], now)
	case "AUTH:PROOF":
		return m.proof(panel, a[0], a[1], a[2], now)
	case "AUTH:ENROL":
		return m.enrol(panel, a[0], a[1], a[2], a[3], now)
	case "SET:SESSION":
		return m.keepAlive(panel, a[0], now)
	case "STOP:SESSION":
		return m.endSession(panel, a[0], now)
	case "GET:ALLOW":
		return m.allow(panel, a[0], a[1], now)
	}

	// The rest administer people, and are themselves actions: MARSHAL.*.
	// GET:GRANTS and SET:USER a person may also do for themselves.
	self := ""
	if key == "GET:GRANTS" || key == "SET:USER" {
		self = a[0]
	}
	if err := m.permit(from, msg.Verb, msg.Noun, self, now); err != nil {
		return "", nil, err
	}
	switch key {
	case "GET:SESSIONS":
		return m.listSessions(now)
	case "GET:USERS":
		return m.listUsers()
	case "NEW:USER":
		return m.newUser(a[0], a[1], a[2], now)
	case "SET:USER":
		return m.setUser(a[0], a[1], a[2])
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

func (m *Marshal) challenge(panel, name string, now time.Time) (string, []string, error) {
	if !auth.ValidName(name) {
		return "", nil, monolink.Fail(monolink.CodeArg, "not a name")
	}
	if err := m.locked(name, now); err != nil {
		return "", nil, err
	}
	for n, ch := range m.challenges {
		if now.After(ch.expires) {
			delete(m.challenges, n)
		}
	}
	if len(m.challenges) >= maxChallenges {
		return "", nil, monolink.Fail(monolink.CodeBusy, "too many sign-ins at once")
	}
	nonce := randHex(16)
	m.challenges[nonce] = challenge{name: name, panel: panel, expires: now.Add(challengeTTL)}
	return auth.NounChallenge, []string{m.kdfFor(name), nonce}, nil
}

// kdfFor is name's KDF or, for a name nobody has, a stand-in salted from
// marshal's secret: stable, so asking twice does not tell who exists.
func (m *Marshal) kdfFor(name string) string {
	if u, ok := m.st.Users[name]; ok {
		return u.KDF
	}
	k, _ := auth.NewKDF()
	mac := hmac.New(sha256.New, []byte(m.st.Secret))
	mac.Write([]byte("kdf\x00" + name))
	k.Salt = mac.Sum(nil)[:len(k.Salt)]
	return k.String()
}

func (m *Marshal) proof(panel, name, nonce, proof string, now time.Time) (string, []string, error) {
	if err := m.locked(name, now); err != nil {
		return "", nil, err
	}
	ch, ok := m.challenges[nonce]
	delete(m.challenges, nonce) // one answer per challenge, right or wrong
	u, exists := m.st.Users[name]
	if !ok || ch.name != name || ch.panel != panel || now.After(ch.expires) || !exists ||
		!auth.CheckProof(u.Verifier, name, panel, nonce, proof) {
		return "", nil, m.failed(name, now)
	}
	delete(m.lockouts, name)
	return m.openSession(name, panel, now)
}

func (m *Marshal) enrol(panel, code, name, kdf, verifier string, now time.Time) (string, []string, error) {
	if m.enrolCode == "" {
		return "", nil, monolink.Fail(monolink.CodeState, "enrolment is closed")
	}
	if err := m.locked(enrolSlot, now); err != nil {
		return "", nil, err
	}
	if subtle.ConstantTimeCompare([]byte(normaliseCode(code)), []byte(normaliseCode(m.enrolCode))) != 1 {
		return "", nil, m.failed(enrolSlot, now)
	}
	if err := checkSecret(name, kdf, verifier); err != nil {
		return "", nil, err
	}
	m.st.Users[name] = &User{KDF: kdf, Verifier: verifier, Grants: []string{"*"}, Created: now}
	m.enrolCode = ""
	delete(m.lockouts, enrolSlot)
	log.Info("ENROLLED", "user", name, "panel", panel)
	return m.openSession(name, panel, now)
}

func checkSecret(name, kdf, verifier string) error {
	if !auth.ValidName(name) {
		return monolink.Fail(monolink.CodeArg, "not a name")
	}
	if _, err := auth.ParseKDF(kdf); err != nil {
		return monolink.Fail(monolink.CodeArg, "unusable kdf")
	}
	if !auth.ValidVerifier(verifier) {
		return monolink.Fail(monolink.CodeArg, "not a verifier")
	}
	return nil
}

// locked refuses a name that is serving a lockout, saying for how long.
func (m *Marshal) locked(name string, now time.Time) error {
	if l := m.lockouts[name]; l != nil && now.Before(l.until) {
		return monolink.Fail(monolink.CodeBusy, strconv.Itoa(int(l.until.Sub(now).Seconds())+1))
	}
	return nil
}

// failed counts a wrong answer. After freeFailures in a row the name is
// locked out, for twice as long each time, up to maxLockout.
func (m *Marshal) failed(name string, now time.Time) error {
	l := m.lockouts[name]
	if l == nil {
		l = &lockout{}
		m.lockouts[name] = l
	}
	l.failures++
	if over := l.failures - freeFailures; over >= 0 {
		d := maxLockout
		if over < 10 {
			d = min(baseLockout<<over, maxLockout)
		}
		l.until = now.Add(d)
		log.Warn("LOCKED OUT", "name", name, "for", d)
	}
	return monolink.Fail(monolink.CodeDenied, "")
}

// ─── sessions ────────────────────────────────────────────────────────

func (m *Marshal) openSession(user, panel string, now time.Time) (string, []string, error) {
	token := randHex(32)
	s := &Session{User: user, Panel: panel, Since: now, Expires: now.Add(m.opt.TTL)}
	m.st.Sessions[hashToken(token)] = s
	if err := m.save(); err != nil {
		delete(m.st.Sessions, hashToken(token))
		return "", nil, err
	}
	log.Info("SIGNED IN", "user", user, "panel", panel)
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

func (m *Marshal) keepAlive(panel, token string, now time.Time) (string, []string, error) {
	s, _, err := m.session(panel, token, now)
	if err != nil {
		return "", nil, err
	}
	s.Expires = now.Add(m.opt.TTL)
	if err := m.save(); err != nil {
		return "", nil, err
	}
	return auth.NounSession, sessionArgs(token, s.User, s.Expires), nil
}

func (m *Marshal) endSession(panel, token string, now time.Time) (string, []string, error) {
	s, h, err := m.session(panel, token, now)
	if err != nil {
		return "", nil, err
	}
	delete(m.st.Sessions, h)
	if err := m.save(); err != nil {
		return "", nil, err
	}
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

func (m *Marshal) listSessions(now time.Time) (string, []string, error) {
	live := make([]*Session, 0, len(m.st.Sessions))
	for _, s := range m.st.Sessions {
		live = append(live, s)
	}
	sort.Slice(live, func(i, j int) bool { return live[i].Since.Before(live[j].Since) })
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

// permit lets a request through if its person's grants cover it, or if it
// concerns only themselves and self names them.
func (m *Marshal) permit(from monolink.Address, verb, noun, self string, now time.Time) error {
	who, ok := m.actor(from, now)
	if !ok {
		return monolink.Fail(monolink.CodeDenied, "sign in first")
	}
	if self != "" && who == self {
		return nil
	}
	action := auth.Action(NodeName, verb, noun)
	if u := m.st.Users[who]; u == nil || !auth.Allowed(u.Grants, action) {
		return monolink.Fail(monolink.CodeDenied, "needs "+action)
	}
	return nil
}

// ─── people and grants ───────────────────────────────────────────────

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

func (m *Marshal) newUser(name, kdf, verifier string, now time.Time) (string, []string, error) {
	if err := checkSecret(name, kdf, verifier); err != nil {
		return "", nil, err
	}
	if _, exists := m.st.Users[name]; exists {
		return "", nil, monolink.Fail(monolink.CodeState, "already exists")
	}
	m.st.Users[name] = &User{KDF: kdf, Verifier: verifier, Grants: []string{}, Created: now}
	if err := m.save(); err != nil {
		delete(m.st.Users, name)
		return "", nil, err
	}
	log.Info("NEW USER", "user", name)
	return auth.NounUser, []string{name}, nil
}

func (m *Marshal) setUser(name, kdf, verifier string) (string, []string, error) {
	u, err := m.user(name)
	if err != nil {
		return "", nil, err
	}
	if err := checkSecret(name, kdf, verifier); err != nil {
		return "", nil, err
	}
	u.KDF, u.Verifier = kdf, verifier
	if err := m.save(); err != nil {
		return "", nil, err
	}
	log.Info("SECRET CHANGED", "user", name)
	return auth.NounUser, []string{name}, nil
}

func (m *Marshal) stopUser(name string) (string, []string, error) {
	u, err := m.user(name)
	if err != nil {
		return "", nil, err
	}
	if slices.Contains(u.Grants, "*") && m.holdersOfAll() == 1 {
		return "", nil, monolink.Fail(monolink.CodeState, "the last person holding * stays")
	}
	delete(m.st.Users, name)
	for h, s := range m.st.Sessions {
		if s.User == name {
			delete(m.st.Sessions, h)
		}
	}
	if err := m.save(); err != nil {
		return "", nil, err
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
		u.Grants = append(u.Grants, pattern)
		if err := m.save(); err != nil {
			return "", nil, err
		}
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
	if pattern == "*" && m.holdersOfAll() == 1 {
		return "", nil, monolink.Fail(monolink.CodeState, "the last person holding * keeps it")
	}
	u.Grants = slices.Delete(u.Grants, i, i+1)
	if err := m.save(); err != nil {
		return "", nil, err
	}
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

// holdersOfAll counts the people granted the whole bubble. It must never
// reach zero, or nobody could administer anyone again.
func (m *Marshal) holdersOfAll() int {
	n := 0
	for _, u := range m.st.Users {
		if slices.Contains(u.Grants, "*") {
			n++
		}
	}
	return n
}

// ─── plumbing ────────────────────────────────────────────────────────

func (m *Marshal) save() error {
	if err := m.store.Save(m.st); err != nil {
		log.Error("SAVE FAILED", "err", err)
		return monolink.Fail(monolink.CodeInternal, "could not save")
	}
	return nil
}

// publish sets marshal's properties; each is announced only if it changed.
func (m *Marshal) publish() {
	m.mu.Lock()
	users, sessions, enrolling := len(m.st.Users), len(m.st.Sessions), m.enrolCode != ""
	names := make([]string, 0, len(m.st.Users))
	for n := range m.st.Users {
		names = append(names, n)
	}
	m.mu.Unlock()
	sort.Strings(names)
	m.users.Set(strconv.Itoa(users))
	m.sessions.Set(strconv.Itoa(sessions))
	m.enrolling.Set(onOff(enrolling))
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

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("marshal: no randomness: " + err.Error())
	}
	return hex.EncodeToString(b)
}
