package marshal

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MrZloHex/monolink"
	auth "github.com/MrZloHex/monolink/marshal"
)

// bus is an in-process concentrator: every frame to every other client,
// understanding none of them — so a test sees exactly what every node on
// the real bus would see.
type bus struct {
	url string

	mu      sync.Mutex
	clients map[*websocket.Conn]bool
	frames  []string
}

func newBus(t *testing.T) *bus {
	t.Helper()
	b := &bus{clients: map[*websocket.Conn]bool{}}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		b.mu.Lock()
		b.clients[c] = true
		b.mu.Unlock()
		defer func() {
			b.mu.Lock()
			delete(b.clients, c)
			b.mu.Unlock()
			c.Close()
		}()
		for {
			mt, data, err := c.ReadMessage()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.frames = append(b.frames, string(data))
			for o := range b.clients {
				if o != c {
					o.WriteMessage(mt, data)
				}
			}
			b.mu.Unlock()
		}
	}))
	t.Cleanup(srv.Close)
	b.url = "ws" + strings.TrimPrefix(srv.URL, "http")
	return b
}

func (b *bus) relayed() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.frames)
}

// heard waits for a frame holding part to cross the bus.
func (b *bus) heard(t *testing.T, part string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !slices.ContainsFunc(b.relayed(), func(f string) bool { return strings.Contains(f, part) }) {
		if time.Now().After(deadline) {
			t.Fatalf("never heard %s; relayed: %q", part, b.relayed())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func quiet() []monolink.Option {
	return []monolink.Option{monolink.WithReconnect(0), monolink.WithLogger(stdlog.New(io.Discard, "", 0))}
}

func (b *bus) panel(t *testing.T, node string) *monolink.Client {
	t.Helper()
	c := monolink.New(node, b.url, quiet()...)
	if err := c.Connect(tctx(t)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

var site = auth.RelyingParty{ID: "monolith-system.net", Origins: []string{"https://monolith-system.net"}}

// startMarshal runs marshal on b with its state at path. The returned stop
// closes it, for tests that restart it.
func startMarshal(t *testing.T, b *bus, path string) (*Marshal, func()) {
	t.Helper()
	c := monolink.New(NodeName, b.url, append(quiet(), monolink.WithDialect(monolink.V2))...)
	m, err := New(c, NewStore(path), Options{TTL: time.Hour, Version: "test", TicketKey: ticketPriv, Site: site})
	if err != nil {
		t.Fatal(err)
	}
	c.Handle("*", m.Cmd)
	if err := c.Connect(tctx(t)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx) // what marshal does unasked: telling the hub about ended tickets
	var once sync.Once
	stop := func() { once.Do(func() { cancel(); c.Close() }) }
	t.Cleanup(stop)
	return m, stop
}

var ticketPub, ticketPriv, _ = ed25519.GenerateKey(rand.Reader)

// tctx bounds a test's requests, so a missing answer fails the test
// instead of hanging it.
func tctx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func code(err error) string {
	var re *monolink.ReplyError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &re):
		return re.Code
	default:
		return "not a reply: " + err.Error()
	}
}

// ─── keys ────────────────────────────────────────────────────────────

// passkey is a phone, in software: a P-256 key answering as a browser on
// the site does.
type passkey struct {
	priv  *ecdsa.PrivateKey
	cred  auth.Credential
	count uint32
}

func newPasskey(t *testing.T, label string) *passkey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	id := make([]byte, 16)
	rand.Read(id)
	return &passkey{priv: priv, cred: auth.Credential{Kind: auth.KindWebAuthn, Alg: auth.AlgES256, Label: label,
		ID: base64.RawURLEncoding.EncodeToString(id), Key: base64.RawURLEncoding.EncodeToString(der)}}
}

func (k *passkey) sign(nonce string) auth.Assertion {
	k.count++
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": nonce, "origin": site.Origins[0], "crossOrigin": false})
	h := sha256.Sum256([]byte(site.ID))
	ad := binary.BigEndian.AppendUint32(append(h[:], 0x05), k.count) // present, verified
	cdh := sha256.Sum256(cd)
	mh := sha256.Sum256(append(slices.Clone(ad), cdh[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, k.priv, mh[:])
	return auth.Assertion{CredentialID: k.cred.ID, AuthData: ad, ClientData: cd, Signature: sig}
}

func (k *passkey) signIn(t *testing.T, c *monolink.Client) (auth.Session, error) {
	t.Helper()
	nonce, err := auth.Challenge(tctx(t), c)
	if err != nil {
		t.Fatal(err)
	}
	return auth.SignInPasskey(tctx(t), c, nonce, k.sign(nonce))
}

// panelKey is monoview's own key.
type panelKey struct {
	priv ed25519.PrivateKey
	cred auth.Credential
}

func newPanelKey(t *testing.T) *panelKey {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cred, err := auth.Ed25519Credential(pub, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	return &panelKey{priv: priv, cred: cred}
}

func (k *panelKey) signIn(t *testing.T, c *monolink.Client, name string) (auth.Session, error) {
	t.Helper()
	return auth.SignInKey(tctx(t), c, name, k.cred.ID, k.priv)
}

// enrolled starts marshal and makes mzh the first person, with monoview's
// key, signed in at MONOVIEW.
func enrolled(t *testing.T) (*bus, *Marshal, *monolink.Client, auth.Session) {
	t.Helper()
	b := newBus(t)
	m, _ := startMarshal(t, b, filepath.Join(t.TempDir(), "marshal.json"))
	mv := b.panel(t, "MONOVIEW")
	s, err := auth.Enrol(tctx(t), mv, strings.ToLower(m.EnrolCode()), "mzh", newPanelKey(t).cred)
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if err := mv.SetActor(s.User); err != nil {
		t.Fatal(err)
	}
	return b, m, mv, s
}

// invited has inviter invite name, and a phone take the invitation up
// through a MONOWEB of its own.
func invited(t *testing.T, b *bus, inviter *monolink.Client, name string) (*monolink.Client, *passkey, auth.Session) {
	t.Helper()
	c, _, err := auth.Invite(tctx(t), inviter, name)
	if err != nil {
		t.Fatalf("invite %s: %v", name, err)
	}
	web := b.panel(t, "MONOWEB")
	k := newPasskey(t, name+"'s phone")
	s, err := auth.Redeem(tctx(t), web, c, name, k.cred)
	if err != nil {
		t.Fatalf("redeem for %s: %v", name, err)
	}
	web.SetActor(name)
	return web, k, s
}

// ─── the first person ────────────────────────────────────────────────

func TestEnrolmentMakesTheFirstPersonOnce(t *testing.T) {
	b := newBus(t)
	m, _ := startMarshal(t, b, filepath.Join(t.TempDir(), "marshal.json"))
	mv := b.panel(t, "MONOVIEW")
	key := newPanelKey(t)
	s, err := auth.Enrol(tctx(t), mv, strings.ToLower(m.EnrolCode()), "mzh", key.cred)
	if err != nil || s.User != "mzh" || s.Token == "" || !s.Expires.After(time.Now()) {
		t.Fatalf("session %+v, %v", s, err)
	}
	mv.SetActor("mzh")
	if m.EnrolCode() != "" {
		t.Fatal("enrolment code survived its use")
	}
	other := b.panel(t, "MONOWEB")
	if _, err := auth.Enrol(tctx(t), other, "0000-0000-0000", "eve", newPasskey(t, "").cred); code(err) != monolink.CodeState {
		t.Fatalf("second enrolment: %v", err)
	}
	if g, err := auth.Grants(tctx(t), mv, "mzh"); err != nil || !slices.Equal(g, []string{"*"}) {
		t.Fatalf("first person's grants %q, %v", g, err)
	}
	if s, err := key.signIn(t, b.panel(t, "MONOVIEW"), "mzh"); err != nil || s.User != "mzh" {
		t.Fatalf("the key signs mzh in again: %+v, %v", s, err)
	}
}

// A code is 60 bits: guessing one is hopeless, so a right code is never
// refused for wrong ones before it. Past five wrong ones, the guesser is
// answered BUSY.
func TestWrongCodesLockOut(t *testing.T) {
	b := newBus(t)
	m, _ := startMarshal(t, b, filepath.Join(t.TempDir(), "marshal.json"))
	mv := b.panel(t, "MONOVIEW")
	for i := 0; i < freeFailures; i++ {
		if _, err := auth.Enrol(tctx(t), mv, "0000-0000-0000", "mzh", newPanelKey(t).cred); code(err) != monolink.CodeDenied {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := auth.Enrol(tctx(t), mv, "0000-0000-0000", "mzh", newPanelKey(t).cred); code(err) != monolink.CodeBusy {
		t.Fatalf("a wrong code during the lockout: %v", err)
	}
	if _, err := auth.Enrol(tctx(t), mv, m.EnrolCode(), "mzh", newPanelKey(t).cred); err != nil {
		t.Fatalf("the right code during the lockout: %v", err)
	}
}

// ─── passkeys ────────────────────────────────────────────────────────

func TestAPasskeySignsIn(t *testing.T) {
	b, _, mv, _ := enrolled(t)
	_, phone, _ := invited(t, b, mv, "dasha")

	web := b.panel(t, "MONOWEB")
	s, err := phone.signIn(t, web)
	if err != nil || s.User != "dasha" {
		t.Fatalf("dasha's passkey: %+v, %v", s, err)
	}

	// A challenge answers once.
	nonce, _ := auth.Challenge(tctx(t), web)
	a := phone.sign(nonce)
	if _, err := auth.SignInPasskey(tctx(t), web, nonce, a); err != nil {
		t.Fatal(err)
	}
	phone.count++ // as if the phone had signed again
	if _, err := auth.SignInPasskey(tctx(t), web, nonce, a); code(err) != monolink.CodeDenied {
		t.Fatalf("an answer replayed: %v", err)
	}
	// A challenge is the panel's that asked for it.
	nonce, _ = auth.Challenge(tctx(t), mv)
	if _, err := auth.SignInPasskey(tctx(t), web, nonce, phone.sign(nonce)); code(err) != monolink.CodeDenied {
		t.Fatalf("another panel's challenge: %v", err)
	}
	// A passkey nobody has.
	if _, err := newPasskey(t, "").signIn(t, web); code(err) != monolink.CodeDenied {
		t.Fatalf("a stranger's passkey: %v", err)
	}
	// A copied passkey: its counter goes back.
	phone.count = 0
	if _, err := phone.signIn(t, web); code(err) != monolink.CodeDenied {
		t.Fatalf("a counter gone back: %v", err)
	}
}

// Nothing signs in by knowing a name: a panel's key answers only for its
// person, and only with its own signature.
func TestAPanelKeyAnswersForItsPersonOnly(t *testing.T) {
	b, _, mv, _ := enrolled(t)
	invited(t, b, mv, "dasha")
	laptop := newPanelKey(t)
	c, _, _ := auth.Invite(tctx(t), mv, "mzh")
	if _, err := auth.Redeem(tctx(t), b.panel(t, "MONOVIEW"), c, "mzh", laptop.cred); err != nil {
		t.Fatal(err)
	}
	other := b.panel(t, "MONOVIEW")
	if _, err := laptop.signIn(t, other, "dasha"); code(err) != monolink.CodeDenied {
		t.Fatalf("mzh's key signed dasha in: %v", err)
	}
	if _, err := auth.SignInKey(tctx(t), other, "mzh", laptop.cred.ID, newPanelKey(t).priv); code(err) != monolink.CodeDenied {
		t.Fatalf("another key's signature: %v", err)
	}
	if s, err := laptop.signIn(t, other, "mzh"); err != nil || s.User != "mzh" {
		t.Fatalf("the key itself: %+v, %v", s, err)
	}
}

// ─── invitations and keys ────────────────────────────────────────────

func TestInvitations(t *testing.T) {
	b, _, mv, _ := enrolled(t)
	web, _, _ := invited(t, b, mv, "dasha")
	if g, _ := auth.Grants(tctx(t), web, "dasha"); len(g) != 0 {
		t.Fatalf("someone new starts with grants %q", g)
	}

	// dasha may invite herself, for another device, and nobody else.
	if _, _, err := auth.Invite(tctx(t), web, "eve"); code(err) != monolink.CodeDenied {
		t.Fatalf("dasha invited someone new: %v", err)
	}
	if _, _, err := auth.Invite(tctx(t), web, "mzh"); code(err) != monolink.CodeDenied {
		t.Fatalf("dasha gave herself a way to be mzh: %v", err)
	}
	c, exp, err := auth.Invite(tctx(t), web, "dasha")
	if err != nil || !exp.After(time.Now()) || exp.After(time.Now().Add(inviteTTL+time.Minute)) {
		t.Fatalf("her own invitation: %s %v, %v", c, exp, err)
	}

	// The code is for dasha, and works once.
	laptop := b.panel(t, "MONOWEB")
	if _, err := auth.Redeem(tctx(t), laptop, c, "eve", newPasskey(t, "").cred); code(err) != monolink.CodeDenied {
		t.Fatalf("dasha's code made eve: %v", err)
	}
	if s, err := auth.Redeem(tctx(t), laptop, strings.ToLower(c), "dasha", newPasskey(t, "laptop").cred); err != nil || s.User != "dasha" {
		t.Fatalf("redeemed: %+v, %v", s, err)
	}
	if _, err := auth.Redeem(tctx(t), laptop, c, "dasha", newPasskey(t, "").cred); code(err) != monolink.CodeDenied {
		t.Fatalf("an invitation used twice: %v", err)
	}
	if u, _ := auth.Users(tctx(t), mv); !slices.Equal(u, []string{"dasha", "mzh"}) {
		t.Fatalf("people %q", u)
	}
}

func TestAPersonLooksAfterTheirKeys(t *testing.T) {
	b, _, mv, _ := enrolled(t)
	web, _, phoneSession := invited(t, b, mv, "dasha")
	c, _, _ := auth.Invite(tctx(t), web, "dasha")
	laptop := b.panel(t, "MONOWEB")
	laptopSession, err := auth.Redeem(tctx(t), laptop, c, "dasha", newPasskey(t, "laptop").cred)
	if err != nil {
		t.Fatal(err)
	}
	laptop.SetActor("dasha")

	keys, err := auth.Keys(tctx(t), web, "dasha")
	if err != nil || len(keys) != 2 || keys[0].Label != "dasha's phone" || keys[1].Label != "laptop" ||
		keys[0].Kind != auth.KindWebAuthn || keys[0].Added.IsZero() {
		t.Fatalf("keys %+v, %v", keys, err)
	}
	if _, err := auth.Keys(tctx(t), web, "mzh"); code(err) != monolink.CodeDenied {
		t.Fatalf("dasha read mzh's keys: %v", err)
	}

	// The phone is lost: removing its key ends what it opened, and only that.
	if err := auth.RemoveKey(tctx(t), laptop, "dasha", keys[0].Ref); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Resume(tctx(t), web, phoneSession.Token); code(err) != monolink.CodeNAC {
		t.Fatalf("the lost phone's session outlived its key: %v", err)
	}
	if _, err := auth.Resume(tctx(t), laptop, laptopSession.Token); err != nil {
		t.Fatalf("the laptop's session ended with it: %v", err)
	}
	b.heard(t, ":MARSHAL:CONCENTRATOR:STOP:TICKETS:dasha")
	if err := auth.RemoveKey(tctx(t), laptop, "dasha", keys[1].Ref); code(err) != monolink.CodeState {
		t.Fatalf("removed the last key: %v", err)
	}
}

func TestAKeyIsNobodysButOnePersons(t *testing.T) {
	b, _, mv, _ := enrolled(t)
	_, phone, _ := invited(t, b, mv, "dasha")
	c, _, _ := auth.Invite(tctx(t), mv, "olga")
	if _, err := auth.Redeem(tctx(t), b.panel(t, "MONOWEB"), c, "olga", phone.cred); code(err) != monolink.CodeState {
		t.Fatalf("dasha's key given to olga too: %v", err)
	}
}

// ─── people and grants ───────────────────────────────────────────────

func TestAdministerPeople(t *testing.T) {
	b, _, mv, _ := enrolled(t)
	ctx := tctx(t)
	web, phone, _ := invited(t, b, mv, "dasha")
	if err := auth.Grant(ctx, mv, "dasha", "VERTEX.*"); err != nil {
		t.Fatal(err)
	}
	ds, err := phone.signIn(t, web)
	if err != nil {
		t.Fatal(err)
	}

	// dasha may read her own grants, and nobody else's, and change none.
	if g, err := auth.Grants(ctx, web, "dasha"); err != nil || !slices.Equal(g, []string{"VERTEX.*"}) {
		t.Fatalf("own grants %q, %v", g, err)
	}
	if _, err := auth.Grants(ctx, web, "mzh"); code(err) != monolink.CodeDenied {
		t.Fatalf("someone else's grants: %v", err)
	}
	if err := auth.Grant(ctx, web, "dasha", "*"); code(err) != monolink.CodeDenied {
		t.Fatalf("dasha granted herself everything: %v", err)
	}

	// GET:ALLOW answers for the grants, and only to the panel holding the token.
	for action, want := range map[string]bool{"VERTEX.SET.LED.BRIGHT": true, "UKAZ.DO.PRINT.TEXT": false} {
		if ok, _, err := auth.Allow(ctx, web, ds.Token, action); err != nil || ok != want {
			t.Errorf("ALLOW %s = %v, %v; want %v", action, ok, err, want)
		}
	}
	if _, _, err := auth.Allow(ctx, mv, ds.Token, "VERTEX.SET.LED.BRIGHT"); code(err) != monolink.CodeNAC {
		t.Fatalf("another panel used dasha's token: %v", err)
	}

	// Nobody can remove the last person holding "*", nor take it from them.
	if err := auth.RemoveUser(ctx, mv, "mzh"); code(err) != monolink.CodeState {
		t.Fatalf("removed the last administrator: %v", err)
	}
	if err := auth.Revoke(ctx, mv, "mzh", "*"); code(err) != monolink.CodeState {
		t.Fatalf("revoked the last *: %v", err)
	}

	// Removing a person ends their sessions, and their keys go with them.
	if err := auth.RemoveUser(ctx, mv, "dasha"); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Resume(ctx, web, ds.Token); code(err) != monolink.CodeNAC {
		t.Fatalf("session outlived its person: %v", err)
	}
	if _, err := phone.signIn(t, web); code(err) != monolink.CodeDenied {
		t.Fatalf("a removed person's passkey: %v", err)
	}
}

// PEOPLE names everyone, for synapse to know whom a message can go to. Any
// node may read it; what each person may do stays behind MARSHAL.*.
func TestPeopleIsReadableAndPublished(t *testing.T) {
	b, _, mv, _ := enrolled(t)
	node := b.panel(t, "SYNAPSE")
	if r, err := node.RequestDialect(tctx(t), monolink.V2, NodeName, monolink.VerbGet, "PEOPLE"); err != nil || r.Arg(0) != "mzh" {
		t.Fatalf("PEOPLE %+v, %v", r, err)
	}
	invited(t, b, mv, "dasha")
	b.heard(t, ":MARSHAL:ALL:PUB:PEOPLE:dasha|mzh")
}

// ─── tickets and sessions ────────────────────────────────────────────

// A ticket is signed for the session's own panel, carries the person's
// grants, and is refused to any other panel holding the token.
func TestATicketIsSignedForTheSessionsPanel(t *testing.T) {
	b, _, mv, s := enrolled(t)
	tk, err := auth.GetTicket(tctx(t), mv, s.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := tk.Check(ticketPub, time.Now()); err != nil {
		t.Fatalf("the ticket does not check: %v", err)
	}
	if tk.Person != "mzh" || tk.Panel != "MONOVIEW" || !slices.Equal(tk.Grants, []string{"*"}) ||
		tk.Expires.After(time.Now().Add(auth.TicketTTL)) {
		t.Fatalf("ticket %+v", tk)
	}
	web := b.panel(t, "MONOWEB")
	if _, err := auth.GetTicket(tctx(t), web, s.Token); code(err) != monolink.CodeNAC {
		t.Fatalf("another panel got a ticket with the token: %v", err)
	}
}

// A change in grants ends the person's tickets at the hub at once.
func TestAGrantEndsTickets(t *testing.T) {
	b, _, mv, _ := enrolled(t)
	invited(t, b, mv, "dasha")
	if err := auth.Grant(tctx(t), mv, "dasha", "VERTEX.*"); err != nil {
		t.Fatal(err)
	}
	b.heard(t, ":MARSHAL:CONCENTRATOR:STOP:TICKETS:dasha")
}

// A session in use stays open: each ticket renewed extends it. One nobody
// renews ends within the TTL.
func TestATicketKeepsItsSessionOpen(t *testing.T) {
	_, m, mv, s := enrolled(t)
	var ahead atomic.Int64
	m.mu.Lock()
	m.now = func() time.Time { return time.Now().Add(time.Duration(ahead.Load())) }
	m.mu.Unlock()

	ahead.Store(int64(50 * time.Minute))
	if _, err := auth.GetTicket(tctx(t), mv, s.Token); err != nil {
		t.Fatal(err)
	}
	ahead.Store(int64(100 * time.Minute))
	if _, err := auth.GetTicket(tctx(t), mv, s.Token); err != nil {
		t.Fatalf("a session in use ended: %v", err)
	}
	ahead.Store(int64(161 * time.Minute))
	if _, err := auth.GetTicket(tctx(t), mv, s.Token); code(err) != monolink.CodeNAC {
		t.Fatalf("a session nobody used for an hour: %v", err)
	}
}

func TestSessionsSurviveARestartAndAreStoredHashed(t *testing.T) {
	b := newBus(t)
	path := filepath.Join(t.TempDir(), "marshal.json")
	m, stop := startMarshal(t, b, path)
	mv := b.panel(t, "MONOVIEW")
	s, err := auth.Enrol(tctx(t), mv, m.EnrolCode(), "mzh", newPanelKey(t).cred)
	if err != nil {
		t.Fatal(err)
	}
	stop()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), s.Token) {
		t.Fatal("session token stored in the clear")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v", fi.Mode().Perm())
	}

	m2, _ := startMarshal(t, b, path)
	if m2.EnrolCode() != "" {
		t.Fatal("enrolment reopened after a restart")
	}
	if got, err := auth.Resume(tctx(t), mv, s.Token); err != nil || got.User != "mzh" {
		t.Fatalf("resume after restart: %+v, %v", got, err)
	}
	if err := auth.SignOut(tctx(t), mv, s.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Resume(tctx(t), mv, s.Token); code(err) != monolink.CodeNAC {
		t.Fatalf("resumed a finished session: %v", err)
	}
}

// A marshal.json from the days of secrets: its people keep their grants and
// lose their secrets, its sessions end, and enrolment opens again, so the
// owner can give themselves a key and invite the rest back.
func TestAStateFromBeforeKeysReopensEnrolment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "marshal.json")
	old := `{"secret":"aa","users":{
	  "mzh":{"kdf":"argon2id|19456|2|1|AAAAAAAAAAAAAAAAAAAAAA","verifier":"bb","grants":["*"],"created":"2026-09-01T00:00:00Z"},
	  "dasha":{"kdf":"argon2id|19456|2|1|AAAAAAAAAAAAAAAAAAAAAA","verifier":"cc","grants":["VERTEX.*"],"created":"2026-09-01T00:00:00Z"}},
	 "sessions":{"dd":{"user":"mzh","panel":"MONOVIEW","since":"2026-09-01T00:00:00Z","expires":"2099-01-01T00:00:00Z"}}}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	b := newBus(t)
	m, _ := startMarshal(t, b, path)
	if m.EnrolCode() == "" {
		t.Fatal("nobody can sign in, and enrolment is closed")
	}
	mv := b.panel(t, "MONOVIEW")
	if _, err := auth.Enrol(tctx(t), mv, m.EnrolCode(), "mzh", newPanelKey(t).cred); err != nil {
		t.Fatal(err)
	}
	mv.SetActor("mzh")
	if ss, err := auth.Sessions(tctx(t), mv); err != nil || len(ss) != 1 {
		t.Fatalf("sessions %+v, %v", ss, err)
	}
	web, _, _ := invited(t, b, mv, "dasha")
	if g, err := auth.Grants(tctx(t), web, "dasha"); err != nil || !slices.Equal(g, []string{"VERTEX.*"}) {
		t.Fatalf("dasha came back with %q, %v", g, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "verifier") || strings.Contains(string(raw), "secret") {
		t.Fatalf("the old secrets were kept: %s", raw)
	}
}
