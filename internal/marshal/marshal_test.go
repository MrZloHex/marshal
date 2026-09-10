package marshal

import (
	"context"
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

// startMarshal runs marshal on b with its state at path. The returned stop
// closes it, for tests that restart it.
func startMarshal(t *testing.T, b *bus, path string) (*Marshal, func()) {
	t.Helper()
	c := monolink.New(NodeName, b.url, append(quiet(), monolink.WithDialect(monolink.V2))...)
	m, err := New(c, NewStore(path), Options{TTL: time.Hour, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	c.Handle("*", m.Cmd)
	if err := c.Connect(tctx(t)); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { c.Close() }) }
	t.Cleanup(stop)
	return m, stop
}

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

// enrolled starts marshal and makes mzh the first person, signed in at
// MONOVIEW.
func enrolled(t *testing.T) (*bus, *Marshal, *monolink.Client, auth.Session) {
	t.Helper()
	b := newBus(t)
	m, _ := startMarshal(t, b, filepath.Join(t.TempDir(), "marshal.json"))
	mv := b.panel(t, "MONOVIEW")
	s, err := auth.Enrol(tctx(t), mv, strings.ToLower(m.EnrolCode()), "mzh", "correct horse battery")
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
	if err := mv.SetActor(s.User); err != nil {
		t.Fatal(err)
	}
	return b, m, mv, s
}

func TestEnrolmentMakesTheFirstPersonOnce(t *testing.T) {
	b, m, mv, s := enrolled(t)
	if s.User != "mzh" || s.Token == "" || !s.Expires.After(time.Now()) {
		t.Fatalf("session %+v", s)
	}
	if m.EnrolCode() != "" {
		t.Fatal("enrolment code survived its use")
	}
	other := b.panel(t, "MONOWEB")
	if _, err := auth.Enrol(tctx(t), other, "0000-0000-0000", "eve", "x"); code(err) != monolink.CodeState {
		t.Fatalf("second enrolment: %v", err)
	}
	if g, err := auth.Grants(tctx(t), mv, "mzh"); err != nil || !slices.Equal(g, []string{"*"}) {
		t.Fatalf("first person's grants %q, %v", g, err)
	}
}

func TestWrongEnrolmentCodeIsDenied(t *testing.T) {
	b := newBus(t)
	startMarshal(t, b, filepath.Join(t.TempDir(), "marshal.json"))
	mv := b.panel(t, "MONOVIEW")
	if _, err := auth.Enrol(tctx(t), mv, "0000-0000-0000", "mzh", "x"); code(err) != monolink.CodeDenied {
		t.Fatalf("wrong code: %v", err)
	}
}

// The concentrator relays every frame to every client, so the secret must
// not be in any of them: not when enrolling, not when signing in.
func TestSecretNeverCrossesTheBus(t *testing.T) {
	b, _, _, _ := enrolled(t)
	web := b.panel(t, "MONOWEB")
	if _, err := auth.SignIn(tctx(t), web, "mzh", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	for _, f := range b.relayed() {
		if strings.Contains(f, "correct horse") {
			t.Fatalf("secret on the wire: %s", f)
		}
	}
}

func TestSignInAndAdministerPeople(t *testing.T) {
	b, _, mv, _ := enrolled(t)
	ctx := tctx(t)

	if err := auth.NewUser(ctx, mv, "dasha", "pa55"); err != nil {
		t.Fatal(err)
	}
	if err := auth.Grant(ctx, mv, "dasha", "VERTEX.*"); err != nil {
		t.Fatal(err)
	}
	if u, err := auth.Users(ctx, mv); err != nil || !slices.Equal(u, []string{"dasha", "mzh"}) {
		t.Fatalf("users %q, %v", u, err)
	}

	web := b.panel(t, "MONOWEB")
	ds, err := auth.SignIn(ctx, web, "dasha", "pa55")
	if err != nil {
		t.Fatal(err)
	}
	web.SetActor("dasha")

	// dasha may look after herself, and nobody else.
	if g, err := auth.Grants(ctx, web, "dasha"); err != nil || !slices.Equal(g, []string{"VERTEX.*"}) {
		t.Fatalf("own grants %q, %v", g, err)
	}
	if _, err := auth.Grants(ctx, web, "mzh"); code(err) != monolink.CodeDenied {
		t.Fatalf("someone else's grants: %v", err)
	}
	if err := auth.NewUser(ctx, web, "eve", "x"); code(err) != monolink.CodeDenied {
		t.Fatalf("dasha added a person: %v", err)
	}
	if err := auth.SetSecret(ctx, web, "dasha", "n3w"); err != nil {
		t.Fatalf("own secret: %v", err)
	}
	if _, err := auth.SignIn(ctx, web, "dasha", "pa55"); code(err) != monolink.CodeDenied {
		t.Fatalf("old secret still works: %v", err)
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

	// Removing a person ends their sessions.
	if err := auth.RemoveUser(ctx, mv, "dasha"); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Resume(ctx, web, ds.Token); code(err) != monolink.CodeNAC {
		t.Fatalf("session outlived its person: %v", err)
	}
}

func TestWrongSecretsLockTheNameOut(t *testing.T) {
	b, _, _, _ := enrolled(t)
	web := b.panel(t, "MONOWEB")
	for i := 0; i < freeFailures; i++ {
		if _, err := auth.SignIn(tctx(t), web, "mzh", "wrong"); code(err) != monolink.CodeDenied {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := auth.SignIn(tctx(t), web, "mzh", "correct horse battery"); code(err) != monolink.CodeBusy {
		t.Fatalf("locked name let in: %v", err)
	}
}

func TestChallengeAnswersOnce(t *testing.T) {
	b, _, _, _ := enrolled(t)
	web := b.panel(t, "MONOWEB")
	ask := func(verb, noun string, args ...string) (monolink.Message, error) {
		return web.RequestDialect(tctx(t), monolink.V2, NodeName, verb, noun, args...)
	}
	r, err := ask(monolink.VerbAuth, auth.NounUser, "mzh")
	if err != nil {
		t.Fatal(err)
	}
	kdf, _ := auth.ParseKDF(r.Args[0])
	nonce := r.Args[1]
	proof := auth.Proof(kdf.Verifier("correct horse battery"), "mzh", "MONOWEB", nonce)
	if _, err := ask(monolink.VerbAuth, auth.NounProof, "mzh", nonce, proof); err != nil {
		t.Fatal(err)
	}
	if _, err := ask(monolink.VerbAuth, auth.NounProof, "mzh", nonce, proof); code(err) != monolink.CodeDenied {
		t.Fatalf("replayed proof: %v", err)
	}
}

// A name nobody has still gets a challenge, the same one each time, so
// asking does not reveal who exists.
func TestUnknownNamesGetAStableChallenge(t *testing.T) {
	b, _, _, _ := enrolled(t)
	web := b.panel(t, "MONOWEB")
	kdf := func() string {
		r, err := web.RequestDialect(tctx(t), monolink.V2, NodeName, monolink.VerbAuth, auth.NounUser, "ghost")
		if err != nil {
			t.Fatal(err)
		}
		return r.Args[0]
	}
	if a, b := kdf(), kdf(); a != b {
		t.Fatalf("stand-in KDF changed: %q then %q", a, b)
	}
	if _, err := auth.SignIn(tctx(t), web, "ghost", "anything"); code(err) != monolink.CodeDenied {
		t.Fatalf("ghost signed in: %v", err)
	}
}

func TestSessionsSurviveARestartAndAreStoredHashed(t *testing.T) {
	b := newBus(t)
	path := filepath.Join(t.TempDir(), "marshal.json")
	m, stop := startMarshal(t, b, path)
	mv := b.panel(t, "MONOVIEW")
	s, err := auth.Enrol(tctx(t), mv, m.EnrolCode(), "mzh", "correct horse battery")
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
