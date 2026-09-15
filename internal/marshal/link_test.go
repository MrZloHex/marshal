package marshal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/MrZloHex/monolink"
)

// linkBrowser is Firefox on Linux as monoweb drives it: a P-256 key it
// cannot export, signing r‖s as WebCrypto does.
type linkBrowser struct {
	key  *ecdsa.PrivateKey
	spki string
}

func newLinkBrowser(t *testing.T) *linkBrowser {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &linkBrowser{key: k, spki: base64.RawURLEncoding.EncodeToString(der)}
}

func (b *linkBrowser) sign(purpose, what, nonce string) string {
	h := sha256.Sum256(linkMessage(purpose, what, nonce))
	r, s, err := ecdsa.Sign(rand.Reader, b.key, h[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

// ask files the browser's request at MONOWEB, as portal passes it on.
func (b *linkBrowser) ask(t *testing.T, m *Marshal) (secret, shown string) {
	t.Helper()
	out := reviewOK(t, m, "MONOWEB", "AUTH", "LINK", b.spki, "firefox", "home")
	return out[0], out[1]
}

// collect answers a challenge of MONOWEB's with the browser's key.
func (b *linkBrowser) collect(m *Marshal, secret string) (string, []string, error) {
	_, ch, err := reviewCall(m, "MONOWEB", "AUTH", "CHALLENGE")
	if err != nil {
		return "", nil, err
	}
	return reviewCall(m, "MONOWEB", "AUTH", "LINKED", secret, ch[0], b.sign("monolith-link", secret, ch[0]))
}

// resume takes a bound session up again, as monoweb does after a reconnect.
func (b *linkBrowser) resume(m *Marshal, token string) (string, []string, error) {
	_, ch, err := reviewCall(m, "MONOWEB", "AUTH", "CHALLENGE")
	if err != nil {
		return "", nil, err
	}
	return reviewCall(m, "MONOWEB", "SET", "SESSION", token, ch[0], b.sign("monolith-resume", token, ch[0]))
}

// linkIn is the whole of it: asked, approved by approver's session, collected.
func linkIn(t *testing.T, m *Marshal, approver string, b *linkBrowser) string {
	t.Helper()
	secret, shown := b.ask(t, m)
	reviewOK(t, m, "MONOWEB.owner", "SET", "LINK", approver, shown)
	_, out, err := b.collect(m, secret)
	if err != nil {
		t.Fatal(err)
	}
	return out[0]
}

func TestABrowserIsSignedInByADeviceThatIs(t *testing.T) {
	m, _, owner := reviewFixture(t)
	b := newLinkBrowser(t)
	secret, shown := b.ask(t, m)

	if st := reviewOK(t, m, "MONOWEB", "AUTH", "LINKED", secret); st[0] != "WAITING" {
		t.Fatalf("before approval: %v", st)
	}
	rec := reviewOK(t, m, "MONOWEB.owner", "GET", "LINK", owner, shown)[0]
	p, err := monolink.SplitRecord(rec)
	if err != nil || len(p) != 5 || p[0] != shown || p[1] != "MONOWEB" || p[3] != "home" || p[4] != "firefox" {
		t.Fatalf("what the owner is asked to approve: %q (%v)", rec, err)
	}
	reviewOK(t, m, "MONOWEB.owner", "SET", "LINK", owner, strings.ToLower(shown)) // typed as a person types
	if st := reviewOK(t, m, "MONOWEB", "AUTH", "LINKED", secret); st[0] != "READY" {
		t.Fatalf("after approval: %v", st)
	}
	_, out, err := b.collect(m, secret)
	if err != nil {
		t.Fatal(err)
	}
	if out[1] != "owner" {
		t.Fatalf("signed in as %q", out[1])
	}
	if tk := reviewTicket(t, m, out[0]); tk.Person != "owner" || tk.Panel != "MONOWEB" {
		t.Fatalf("its ticket: %+v", tk)
	}
	if _, _, err := b.collect(m, secret); code(err) != monolink.CodeNAC {
		t.Fatalf("collected twice: %v", err)
	}
	st, err := m.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if s := st.Sessions[hashToken(out[0])]; s == nil || s.Bound != b.spki {
		t.Fatal("the approved session is not saved bound to the browser's key")
	}
}

func TestAnApprovedBrowserChangesNothing(t *testing.T) {
	m, _, owner := reviewFixture(t)
	token := linkIn(t, m, owner, newLinkBrowser(t))
	for _, c := range []struct {
		verb, noun string
		args       []string
	}{
		{"NEW", "INVITE", []string{token, "owner"}},
		{"NEW", "INVITE", []string{token, "guest"}},
		{"SET", "GRANT", []string{token, "owner", "VERTEX.*"}},
	} {
		if _, _, err := reviewCall(m, "MONOWEB.owner", c.verb, c.noun, c.args...); code(err) != monolink.CodeDenied {
			t.Errorf("%s:%s from an approved browser: %v", c.verb, c.noun, err)
		}
	}
	_, other := newLinkBrowser(t).ask(t, m)
	if _, _, err := reviewCall(m, "MONOWEB.owner", "SET", "LINK", token, other); code(err) != monolink.CodeDenied {
		t.Fatalf("an approved browser approved another: %v", err)
	}
	reviewOK(t, m, "MONOWEB.owner", "STOP", "SESSIONS", token, "owner") // signing oneself out everywhere, it may
}

func TestOnlyTheBrowserThatAskedCollects(t *testing.T) {
	m, _, owner := reviewFixture(t)
	b := newLinkBrowser(t)
	secret, shown := b.ask(t, m)
	if _, _, err := b.collect(m, secret); code(err) != monolink.CodeState {
		t.Fatalf("collected before approval: %v", err)
	}
	reviewOK(t, m, "MONOWEB.owner", "SET", "LINK", owner, shown)

	if _, _, err := newLinkBrowser(t).collect(m, secret); code(err) != monolink.CodeDenied {
		t.Fatalf("another key, with the secret: %v", err)
	}
	_, ch, _ := reviewCall(m, "MONOVIEW", "AUTH", "CHALLENGE")
	if _, _, err := reviewCall(m, "MONOWEB", "AUTH", "LINKED", secret, ch[0], b.sign("monolith-link", secret, ch[0])); code(err) != monolink.CodeDenied {
		t.Fatalf("with another panel's challenge: %v", err)
	}
	_, ch, _ = reviewCall(m, "MONOVIEW", "AUTH", "CHALLENGE")
	if _, _, err := reviewCall(m, "MONOVIEW", "AUTH", "LINKED", secret, ch[0], b.sign("monolith-link", secret, ch[0])); code(err) != monolink.CodeNAC {
		t.Fatalf("collected at another panel: %v", err)
	}
	if _, _, err := b.collect(m, secret); err != nil {
		t.Fatalf("the browser that asked: %v", err)
	}
}

func TestAnApprovedBrowserResumesOnlyWithItsKey(t *testing.T) {
	m, _, owner := reviewFixture(t)
	b := newLinkBrowser(t)
	token := linkIn(t, m, owner, b)
	if _, _, err := reviewCall(m, "MONOWEB", "SET", "SESSION", token); code(err) != monolink.CodeDenied {
		t.Fatalf("taken up with the token alone: %v", err)
	}
	if _, _, err := newLinkBrowser(t).resume(m, token); code(err) != monolink.CodeDenied {
		t.Fatalf("taken up with another key: %v", err)
	}
	if _, _, err := b.resume(m, token); err != nil {
		t.Fatalf("taken up by its own browser: %v", err)
	}
	// A session of a key's own takes no proof, and is refused one.
	if _, _, err := reviewCall(m, "MONOWEB", "SET", "SESSION", owner, "x", "y"); code(err) != monolink.CodeArgc {
		t.Fatalf("a proof for a key's own session: %v", err)
	}
	reviewOK(t, m, "MONOWEB", "SET", "SESSION", owner)
}

func TestApprovingNeedsAFreshSignInAndLookingDoesNot(t *testing.T) {
	m, _, owner := reviewFixture(t)
	setNow(m, m.now().Add(freshSignIn+time.Minute))
	_, shown := newLinkBrowser(t).ask(t, m)
	reviewOK(t, m, "MONOWEB.owner", "GET", "LINK", owner, shown)
	if _, _, err := reviewCall(m, "MONOWEB.owner", "SET", "LINK", owner, shown); code(err) != monolink.CodeDenied {
		t.Fatalf("approved from a stale sign-in: %v", err)
	}
	reviewOK(t, m, "MONOWEB.owner", "STOP", "LINK", owner, shown) // refusing needs no fingerprint
}

func TestACodeLastsTwoMinutes(t *testing.T) {
	m, _, owner := reviewFixture(t)
	secret, shown := newLinkBrowser(t).ask(t, m)
	setNow(m, m.now().Add(linkTTL))
	if _, _, err := reviewCall(m, "MONOWEB", "AUTH", "LINKED", secret); code(err) != monolink.CodeNAC {
		t.Fatalf("still waiting after two minutes: %v", err)
	}
	if _, _, err := reviewCall(m, "MONOWEB.owner", "GET", "LINK", owner, shown); code(err) != monolink.CodeDenied {
		t.Fatalf("an old code shown: %v", err)
	}
}

func TestARefusedBrowserFindsNothing(t *testing.T) {
	m, _, owner := reviewFixture(t)
	secret, shown := newLinkBrowser(t).ask(t, m)
	reviewOK(t, m, "MONOWEB.owner", "STOP", "LINK", owner, shown)
	if _, _, err := reviewCall(m, "MONOWEB", "AUTH", "LINKED", secret); code(err) != monolink.CodeNAC {
		t.Fatalf("a refused browser: %v", err)
	}
}

// The approving key removed, or its person signed out everywhere, before or
// after the browser collects: the browser is out too.
func TestAnApprovalGoesWithTheKeyThatGaveIt(t *testing.T) {
	m, key, owner := reviewFixture(t)
	b := newLinkBrowser(t)
	token := linkIn(t, m, owner, b)

	// a second key, so that the first may go
	iv := reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", owner, "owner")[0]
	phone := newPasskey(t, "phone")
	phoneToken := reviewOK(t, m, "MONOWEB", "AUTH", "REDEEM", reg(iv, "owner", phone.cred, phone.answer(t, m, "MONOWEB"))...)[0]
	reviewOK(t, m, "MONOWEB.owner", "STOP", "KEY", phoneToken, "owner", key.cred.Ref())
	if _, _, err := b.resume(m, token); code(err) != monolink.CodeNAC {
		t.Fatalf("the browser outlived the key that approved it: %v", err)
	}

	// approved, then everything ended before it collects
	b2 := newLinkBrowser(t)
	secret, shown := b2.ask(t, m)
	reviewOK(t, m, "MONOWEB.owner", "SET", "LINK", phoneToken, shown)
	reviewOK(t, m, "MONOWEB.owner", "STOP", "SESSIONS", phoneToken, "owner")
	if _, _, err := b2.collect(m, secret); code(err) != monolink.CodeNAC {
		t.Fatalf("collected an approval withdrawn: %v", err)
	}
}

func TestAnApprovedBrowserLastsHoursNotAMonth(t *testing.T) {
	m, _, owner := reviewFixture(t)
	b := newLinkBrowser(t)
	token := linkIn(t, m, owner, b)
	start := m.now()
	for i := 1; ; i++ {
		now := start.Add(time.Duration(i) * 50 * time.Minute)
		setNow(m, now)
		_, out, err := b.resume(m, token)
		if err != nil {
			if now.Sub(start) <= linkMaxAge-time.Hour {
				t.Fatalf("ended after %v: %v", now.Sub(start), err)
			}
			return
		}
		if exp, _ := time.Parse(time.RFC3339, out[2]); exp.After(start.Add(linkMaxAge)) {
			t.Fatalf("renewed until %v, past %v", exp, linkMaxAge)
		}
		if i > 40 {
			t.Fatal("never ended")
		}
	}
}

func TestWrongCodesAreCountedAndARightOneStillWorks(t *testing.T) {
	m, _, owner := reviewFixture(t)
	var err error
	for i := 0; i <= freeFailures; i++ {
		_, _, err = reviewCall(m, "MONOWEB.owner", "GET", "LINK", owner, "AAAA-AAAA")
	}
	if code(err) != monolink.CodeBusy {
		t.Fatalf("wrong codes are not counted: %v", err)
	}
	_, shown := newLinkBrowser(t).ask(t, m)
	reviewOK(t, m, "MONOWEB.owner", "GET", "LINK", owner, shown)
}

func TestWhatABrowserSaysIsChecked(t *testing.T) {
	m, _, _ := reviewFixture(t)
	b := newLinkBrowser(t)
	for _, args := range [][]string{
		{"not-a-key", "firefox", "home"},
		{b.spki, "fire:fox", "home"},
		{b.spki, "firefox", "ho\x1bme"},
	} {
		if _, _, err := reviewCall(m, "MONOWEB", "AUTH", "LINK", args...); code(err) != monolink.CodeArg {
			t.Errorf("%q: %v", args, err)
		}
	}
	for i := 0; i < maxLinksAt; i++ {
		b.ask(t, m)
	}
	if _, _, err := reviewCall(m, "MONOWEB", "AUTH", "LINK", b.spki, "firefox", "home"); code(err) != monolink.CodeBusy {
		t.Fatalf("more waiting from one place than it may have: %v", err)
	}
	// Somewhere else is not held up by it — until the panel is full.
	for i := 0; i < maxLinks-maxLinksAt; i++ {
		reviewOK(t, m, "MONOWEB", "AUTH", "LINK", b.spki, "firefox", "203.0.113."+string(rune('a'+i/maxLinksAt)))
	}
	if _, _, err := reviewCall(m, "MONOWEB", "AUTH", "LINK", b.spki, "firefox", "198.51.100.1"); code(err) != monolink.CodeBusy {
		t.Fatalf("more waiting than a panel may have: %v", err)
	}
}

// A ticket, or what a session may do, is asked by its panel or by its own
// person: someone else signed in at MONOWEB gets nothing for a token — not
// even for an approved browser's, which is worth its key, not its token.
func TestATokenGetsNoTicketForSomeoneElse(t *testing.T) {
	m, _, owner := reviewFixture(t)
	bound := linkIn(t, m, owner, newLinkBrowser(t))
	for _, token := range []string{owner, bound} {
		if _, _, err := reviewCall(m, "MONOWEB.dasha", "GET", "TICKET", token); code(err) != monolink.CodeDenied {
			t.Fatalf("someone else had the owner's ticket signed: %v", err)
		}
		if _, _, err := reviewCall(m, "MONOWEB.dasha", "GET", "ALLOW", token, "MARSHAL.GET.USERS"); code(err) != monolink.CodeDenied {
			t.Fatalf("someone else asked what the owner's session may do: %v", err)
		}
		reviewOK(t, m, "MONOWEB", "GET", "TICKET", token)       // portal, for the browser
		reviewOK(t, m, "MONOWEB.owner", "GET", "TICKET", token) // the person themselves
	}
}

// A key and signatures made by WebCrypto itself (node, crypto.subtle), as
// monoweb makes them: marshal takes exactly what a browser sends.
func TestAWebCryptoSignatureIsTaken(t *testing.T) {
	const (
		spki   = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPeJKx-T3muNiib1ClVYoi1NoM1QBU6wss3gp-gh867SAtNIgjd2gaUSTB2_Ea6sl_yRLxcfF0W71QAPUyX4rbA"
		secret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA"
		nonce  = "bm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9uY2Utbm9uYw"
		link   = "DGCrAKVvQJHbGBrBKOD7b6LmeNz7xxtgH-NU2yyIeGuaIMwlsejJViS-6bo-I49GNEI4jOSTdlwp4ExHwFio_Q"
		resume = "2oamKlpNBR3yNV38fFfeLhZ2fblT0y-R4gFYe-YY4wO5oEWGotlDWy2zOPhTnqHESbiWxWJi0-8Jq-qe72FWJQ"
	)
	k, err := parseLinkKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyLinkSig(k, linkMessage("monolith-link", secret, nonce), link) {
		t.Error("a WebCrypto link signature was refused")
	}
	if !verifyLinkSig(k, linkMessage("monolith-resume", "the-token", nonce), resume) {
		t.Error("a WebCrypto resume signature was refused")
	}
	if verifyLinkSig(k, linkMessage("monolith-resume", secret, nonce), link) {
		t.Error("a signature was taken for another purpose than it was made for")
	}
}
