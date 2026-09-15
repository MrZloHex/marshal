package marshal

// A review on 2026-09-12 reproduced each of these as a weakness (its report
// is kept outside the repository). Here they are the invariants that hold
// now.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/MrZloHex/monolink"
	auth "github.com/MrZloHex/monolink/marshal"
)

// reviewFixture is marshal on a clock that stands still, with owner enrolled
// at MONOWEB: the marshal, owner's key, and the session's token.
func reviewFixture(t *testing.T) (*Marshal, *panelKey, string) {
	t.Helper()
	c := monolink.New(NodeName, "ws://unused", quiet()...)
	t.Cleanup(func() { c.Close() })
	m, err := New(c, NewStore(filepath.Join(t.TempDir(), "state.json")), Options{TTL: time.Hour, TicketKey: ticketPriv, Site: site})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Millisecond)
	m.now = func() time.Time { return now }
	key := newPanelKey(t)
	token := reviewOK(t, m, "MONOWEB", "AUTH", "ENROL", reg(m.EnrolCode(), "owner", key.cred, key.answer(t, m, "MONOWEB", "owner"))...)[0]
	return m, key, token
}

func reviewCall(m *Marshal, from, verb, noun string, args ...string) (string, []string, error) {
	return m.serve(monolink.Message{Version: monolink.V2, ID: "rv", From: from, To: NodeName, Verb: verb, Noun: noun, Args: args})
}

func reviewOK(t *testing.T, m *Marshal, from, verb, noun string, args ...string) []string {
	t.Helper()
	_, out, err := reviewCall(m, from, verb, noun, args...)
	if err != nil {
		t.Fatalf("%s %s:%s: %v", from, verb, noun, err)
	}
	return out
}

func reviewTicket(t *testing.T, m *Marshal, token string) auth.Ticket {
	t.Helper()
	tk, err := auth.ParseTicket(reviewOK(t, m, "MONOWEB", "GET", "TICKET", token))
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

// reg is AUTH:ENROL's and AUTH:REDEEM's arguments.
func reg(code, name string, c auth.Credential, proof []string) []string {
	return append(append([]string{code, name}, c.Args()...), proof...)
}

// answer is a panel key's proof: its signature for name at panel, over a
// challenge of panel's.
func (k *panelKey) answer(t *testing.T, m *Marshal, panel, name string) []string {
	t.Helper()
	nonce := reviewOK(t, m, panel, "AUTH", "CHALLENGE")[0]
	return []string{nonce, base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.priv, auth.KeyMessage(name, panel, nonce)))}
}

// answer is a passkey's proof: its assertion over a challenge of panel's.
func (k *passkey) answer(t *testing.T, m *Marshal, panel string) []string {
	t.Helper()
	nonce := reviewOK(t, m, panel, "AUTH", "CHALLENGE")[0]
	return auth.PasskeyArgs(nonce, k.sign(nonce))
}

// F01, W01: a change needs its own session to be a recent sign-in. Another
// session's — the same person's, at the same panel name, as every browser is
// MONOWEB — lends it nothing; and removing keys, changing grants and
// removing people need it as much as inviting does.
func TestAChangeNeedsItsOwnSessionFresh(t *testing.T) {
	m, key, old := reviewFixture(t)
	iv := reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", old, "guest")[0]
	guest := newPasskey(t, "phone")
	guestToken := reviewOK(t, m, "MONOWEB", "AUTH", "REDEEM", reg(iv, "guest", guest.cred, guest.answer(t, m, "MONOWEB"))...)[0]

	later := m.now().Add(freshSignIn + time.Minute)
	m.now = func() time.Time { return later }
	changes := [][]string{
		{"NEW", "INVITE", "owner"},
		{"STOP", "KEY", "owner", key.cred.Ref()},
		{"SET", "GRANT", "guest", "VERTEX.*"},
		{"STOP", "GRANT", "owner", "*"},
		{"STOP", "USER", "guest"},
		{"STOP", "SESSIONS", "guest"},
	}
	refused := func(why, from, token string) {
		t.Helper()
		for _, c := range changes {
			args := append([]string{token}, c[2:]...)
			if _, _, err := reviewCall(m, from, c[0], c[1], args...); code(err) != monolink.CodeDenied {
				t.Errorf("%s: %s:%s %v", why, c[0], c[1], err)
			}
		}
	}
	refused("from a sign-in long past", "MONOWEB.owner", old)

	// The owner signs in again, in another browser: the old session is no
	// fresher for it.
	nonce := reviewOK(t, m, "MONOWEB", "AUTH", "CHALLENGE")[0]
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(key.priv, auth.KeyMessage("owner", "MONOWEB", nonce)))
	fresh := reviewOK(t, m, "MONOWEB", "AUTH", "KEY", nonce, "owner", key.cred.ID, sig)[0]
	refused("another session's sign-in lent the old one its freshness", "MONOWEB.owner", old)
	refused("a session named by someone not its person", "MONOWEB.guest", fresh)
	refused("no session at all", "MONOWEB.owner", "nonsense")

	reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", fresh, "owner")
	reviewOK(t, m, "MONOWEB.owner", "SET", "GRANT", fresh, "guest", "VERTEX.*")
	// Signing oneself out everywhere takes nothing but sessions, and needs
	// only a session.
	reviewOK(t, m, "MONOWEB.guest", "STOP", "SESSIONS", guestToken, "guest")
}

// I1, W05: a key is taken only from whoever holds it — its answer to a
// challenge of that panel's, for that name — and a wrong answer keeps the
// invitation for the key's holder.
func TestAKeyIsTakenOnlyFromItsHolder(t *testing.T) {
	m, _, token := reviewFixture(t)
	iv := reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", token, "guest")[0]
	phone, thief, laptop := newPasskey(t, "phone"), newPasskey(t, ""), newPanelKey(t)

	forged := func() []string {
		nonce := reviewOK(t, m, "MONOWEB", "AUTH", "CHALLENGE")[0]
		a := thief.sign(nonce)
		a.CredentialID = phone.cred.ID
		return auth.PasskeyArgs(nonce, a)
	}()
	elsewhere := phone.answer(t, m, "MONOVIEW")
	unasked := auth.PasskeyArgs("bm9uY2U", phone.sign("bm9uY2U"))
	for why, try := range map[string][]string{
		"another passkey's answer":          reg(iv, "guest", phone.cred, thief.answer(t, m, "MONOWEB")),
		"another key's signature under its": reg(iv, "guest", phone.cred, forged),
		"another panel's challenge":         reg(iv, "guest", phone.cred, elsewhere),
		"a challenge nobody asked for":      reg(iv, "guest", phone.cred, unasked),
		"a panel key signing another name":  reg(iv, "guest", laptop.cred, laptop.answer(t, m, "MONOWEB", "owner")),
		"a panel key signing for another":   reg(iv, "guest", laptop.cred, laptop.answer(t, m, "MONOVIEW", "guest")),
	} {
		if _, _, err := reviewCall(m, "MONOWEB", "AUTH", "REDEEM", try...); code(err) != monolink.CodeDenied {
			t.Errorf("%s: %v", why, err)
		}
	}
	if len(m.st.Users) != 1 {
		t.Fatal("someone was made of a key nobody proved")
	}
	s := reviewOK(t, m, "MONOWEB", "AUTH", "REDEEM", reg(iv, "guest", phone.cred, phone.answer(t, m, "MONOWEB"))...)
	if s[1] != "guest" || m.st.Users["guest"].Keys[0].Count != phone.count {
		t.Fatalf("the holder's own key: %q, counter %d", s, m.st.Users["guest"].Keys[0].Count)
	}
}

// F02: removing a stolen key voids what it made while it was trusted — a
// self-invitation would otherwise let the thief register a new key.
func TestAnInvitationDiesWithTheKeyThatMadeIt(t *testing.T) {
	m, stolen, token := reviewFixture(t)
	iv := reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", token, "owner")[0]
	laptop := newPanelKey(t)
	laptopToken := reviewOK(t, m, "MONOVIEW", "AUTH", "REDEEM", reg(iv, "owner", laptop.cred, laptop.answer(t, m, "MONOVIEW", "owner"))...)[0]
	backdoor := reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", token, "owner")[0]
	reviewOK(t, m, "MONOVIEW.owner", "STOP", "KEY", laptopToken, "owner", stolen.cred.Ref())
	thief := newPanelKey(t)
	_, _, err := reviewCall(m, "MONOWEB", "AUTH", "REDEEM", reg(backdoor, "owner", thief.cred, thief.answer(t, m, "MONOWEB", "owner"))...)
	if code(err) != monolink.CodeState {
		t.Fatalf("an invitation outlived the key that made it: %v", err)
	}
}

// F03: signing out, and a session evicted, end the tickets — the hub
// cannot tell one session's tickets from another's, so all of the person's.
func TestAnEndedSessionEndsItsTickets(t *testing.T) {
	for _, how := range []string{"signing out", "eviction"} {
		t.Run(how, func(t *testing.T) {
			m, key, token := reviewFixture(t)
			tk := reviewTicket(t, m, token)
			if how == "signing out" {
				reviewOK(t, m, "MONOWEB", "STOP", "SESSION", token)
			} else {
				// Later than the first, so the first is the oldest and the
				// one evicted: at one instant, which goes would be chance.
				later := m.now().Add(time.Second)
				for range maxSessions {
					if _, _, err := m.openSession("owner", "MONOWEB", key.cred.Ref(), "", later); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, ok := m.st.Sessions[hashToken(token)]; ok {
				t.Fatal("the session is still open")
			}
			if tk.Issued.After(m.ended["owner"]) {
				t.Fatal("the ended session's ticket still stands")
			}
			if _, ok := m.st.Ending["owner"]; !ok {
				t.Fatal("the cutoff is not kept for the hub")
			}
		})
	}
}

// F04: a revocation covers every ticket signed before it, even one signed in
// the same millisecond and dated a millisecond ahead.
func TestARevocationCoversEveryTicketBeforeIt(t *testing.T) {
	m, _, token := reviewFixture(t)
	m.st.Users["owner"].Grants = []string{"MARSHAL.SET.GRANT", "MARSHAL.STOP.GRANT", "VERTEX.*"}
	reviewOK(t, m, "MONOWEB.owner", "SET", "GRANT", token, "owner", "VERTEX.GET.LED")
	tk := reviewTicket(t, m, token)
	reviewOK(t, m, "MONOWEB.owner", "STOP", "GRANT", token, "owner", "VERTEX.*")
	if tk.Issued.After(m.ended["owner"]) {
		t.Fatalf("a ticket signed at %v outlives the cutoff at %v", tk.Issued, m.ended["owner"])
	}
}

// F05: an ended ticket's cutoff is saved with the change, survives a
// restart, and is let go only once every ticket it covers has expired.
func TestAnEndedTicketIsKeptUntilTheHubHasIt(t *testing.T) {
	m, _, token := reviewFixture(t)
	reviewOK(t, m, "MONOWEB.owner", "SET", "GRANT", token, "owner", "VERTEX.*")
	disk, err := m.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cut, ok := disk.Ending["owner"]
	if !ok {
		t.Fatal("the cutoff was not saved with the change")
	}
	c := monolink.New(NodeName, "ws://unused", quiet()...)
	defer c.Close()
	again, err := New(c, m.store, Options{TTL: time.Hour, TicketKey: ticketPriv, Site: site})
	if err != nil {
		t.Fatal(err)
	}
	if !again.ended["owner"].Equal(cut) {
		t.Fatal("a restart forgot the cutoff")
	}
	later := cut.Add(auth.TicketTTL + auth.ClockSkew + time.Minute)
	again.now = func() time.Time { return later }
	again.sendEndings(context.Background())
	if len(again.st.Ending) != 0 {
		t.Fatal("a cutoff whose tickets have all expired is still kept")
	}
}

// F06: no more grants than a ticket carries, or the person gets no ticket.
func TestNoGrantBeyondWhatATicketHolds(t *testing.T) {
	m, _, token := reviewFixture(t)
	for i := len(m.st.Users["owner"].Grants); i < auth.MaxTicketGrants; i++ {
		reviewOK(t, m, "MONOWEB.owner", "SET", "GRANT", token, "owner", fmt.Sprintf("VERTEX.GET.P%d", i))
	}
	if _, _, err := reviewCall(m, "MONOWEB.owner", "SET", "GRANT", token, "owner", "VERTEX.GET.ONE.TOO.MANY"); code(err) != monolink.CodeState {
		t.Fatalf("a grant beyond a ticket's: %v", err)
	}
	reviewTicket(t, m, token)
}

// F07: nobody can take every invitation. A newer one for the same name
// replaces the older, and each inviter has a few at most.
func TestNobodyTakesEveryInvitation(t *testing.T) {
	m, _, token := reviewFixture(t)
	iv := reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", token, "guest")[0]
	key := newPanelKey(t)
	guestToken := reviewOK(t, m, "MONOWEB", "AUTH", "REDEEM", reg(iv, "guest", key.cred, key.answer(t, m, "MONOWEB", "guest"))...)[0]
	for range maxInvites + 1 {
		reviewOK(t, m, "MONOWEB.guest", "NEW", "INVITE", guestToken, "guest")
	}
	for i := range maxInvitesEach {
		reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", token, fmt.Sprintf("someone%d", i))
	}
	if _, _, err := reviewCall(m, "MONOWEB.owner", "NEW", "INVITE", token, "one-too-many"); code(err) != monolink.CodeBusy {
		t.Fatalf("an inviter beyond their quota: %v", err)
	}
}

// F08: a stranger's wrong guesses never block a right code: codes are 60
// bits. Past five, the guesser is told to wait.
func TestAStrangersGuessesDoNotBlockARightCode(t *testing.T) {
	m, _, token := reviewFixture(t)
	iv := reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", token, "guest")[0]
	pass := newPasskey(t, "guest")
	guess := func() error {
		_, _, err := reviewCall(m, "MONOWEB", "AUTH", "REDEEM", reg("0000-0000-0000", "guest", pass.cred, pass.answer(t, m, "MONOWEB"))...)
		return err
	}
	for range freeFailures {
		guess()
	}
	if err := guess(); code(err) != monolink.CodeBusy {
		t.Fatalf("a guesser past five tries: %v", err)
	}
	reviewOK(t, m, "MONOWEB", "AUTH", "REDEEM", reg(iv, "guest", pass.cred, pass.answer(t, m, "MONOWEB"))...)
}

// F09: every answer fits a frame, and PEOPLE always names everyone.
func TestEveryAnswerFitsAFrame(t *testing.T) {
	t.Run("sessions", func(t *testing.T) {
		m, _, _ := reviewFixture(t)
		for i := range monolink.MaxArgs + 4 {
			name := fmt.Sprintf("p%d", i)
			m.st.Sessions[name] = &Session{User: name, Panel: "MONOWEB", Key: "k", Since: m.now(), Expires: m.now().Add(time.Hour)}
		}
		out := reviewOK(t, m, "MONOWEB.owner", "GET", "SESSIONS")
		if _, err := (monolink.Message{Version: monolink.V2, ID: "rv", From: NodeName, To: "MONOWEB.owner", Verb: "OK", Noun: "SESSIONS", Args: out}).Marshal(); err != nil {
			t.Fatalf("GET:SESSIONS does not fit a frame: %v", err)
		}
	})
	t.Run("people", func(t *testing.T) {
		m, _, token := reviewFixture(t)
		for i := 0; ; i++ {
			name := fmt.Sprintf("%030d", i)
			_, _, err := reviewCall(m, "MONOWEB.owner", "NEW", "INVITE", token, name)
			if err != nil {
				if code(err) != monolink.CodeState {
					t.Fatalf("a person too many: %v", err)
				}
				break
			}
			m.invites = map[string]invite{}
			m.st.Users[name] = &User{Grants: []string{}} // as if the invitation were taken up
			if i > maxPeople {
				t.Fatal("never refused a person too many")
			}
		}
		m.publish()
		names := make([]string, 0, len(m.st.Users))
		for n := range m.st.Users {
			names = append(names, n)
		}
		sort.Strings(names)
		if m.people.Get() != monolink.Record(names...) {
			t.Fatal("PEOPLE does not name everyone")
		}
	})
}

// F10: a change that fails to save leaves memory as the file is.
func TestAFailedSaveChangesNothing(t *testing.T) {
	for _, action := range []string{"SET", "GET", "STOP"} {
		t.Run(action, func(t *testing.T) {
			m, _, token := reviewFixture(t)
			was := m.st.Sessions[hashToken(token)].Expires
			later := m.now().Add(10 * time.Minute)
			m.now = func() time.Time { return later }
			m.store = NewStore(filepath.Join(t.TempDir(), "missing", "state.json"))
			noun := "SESSION"
			if action == "GET" {
				noun = "TICKET"
			}
			if _, _, err := reviewCall(m, "MONOWEB", action, noun, token); code(err) != monolink.CodeInternal {
				t.Fatalf("expected the save to fail: %v", err)
			}
			if s := m.st.Sessions[hashToken(token)]; s == nil || !s.Expires.Equal(was) {
				t.Fatal("a failed save changed the session in memory")
			}
		})
	}
	t.Run("passkey counter", func(t *testing.T) {
		m, _, token := reviewFixture(t)
		pass := newPasskey(t, "phone")
		iv := reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", token, "guest")[0]
		reviewOK(t, m, "MONOWEB", "AUTH", "REDEEM", reg(iv, "guest", pass.cred, pass.answer(t, m, "MONOWEB"))...)
		was := m.st.Users["guest"].Keys[0].Count
		m.store = NewStore(filepath.Join(t.TempDir(), "missing", "state.json"))
		nonce := reviewOK(t, m, "MONOWEB", "AUTH", "CHALLENGE")[0]
		if _, _, err := reviewCall(m, "MONOWEB", "AUTH", "PASSKEY", auth.PasskeyArgs(nonce, pass.sign(nonce))...); code(err) != monolink.CodeInternal {
			t.Fatalf("expected the save to fail: %v", err)
		}
		if m.st.Users["guest"].Keys[0].Count != was {
			t.Fatal("a failed sign-in moved the counter in memory")
		}
	})
}

// F11: a directory that cannot be synced fails the save before anything
// changes, so memory and file agree.
func TestASaveThatCannotSyncItsDirectoryChangesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	m, _, token := reviewFixture(t)
	dir := filepath.Dir(m.store.path)
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	_, _, err := reviewCall(m, "MONOWEB.owner", "SET", "GRANT", token, "owner", "UKAZ.*")
	os.Chmod(dir, 0o700)
	if code(err) != monolink.CodeInternal {
		t.Fatalf("expected the save to fail: %v", err)
	}
	disk, err := m.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.st.Users["owner"].Grants) != 1 || len(disk.Users["owner"].Grants) != 1 {
		t.Fatalf("memory has %d grants, the file %d", len(m.st.Users["owner"].Grants), len(disk.Users["owner"].Grants))
	}
}

// F12: a state that parses but cannot be right is refused, not crashed on;
// what is merely stale is dropped.
func TestABrokenStateIsRefused(t *testing.T) {
	load := func(raw string) (*Marshal, error) {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		c := monolink.New(NodeName, "ws://unused", quiet()...)
		t.Cleanup(func() { c.Close() })
		return New(c, NewStore(path), Options{})
	}
	// Nine long names: more than PEOPLE's one field can carry.
	var crowd []string
	for i := range 9 {
		crowd = append(crowd, fmt.Sprintf(`"%030d":{}`, i))
	}
	for _, raw := range []string{`{"users":{"owner":null}}`, `{"users":{"owner":{"keys":[null]}}}`, `{"users":{"Not A Name":{}}}`,
		`{"users":{` + strings.Join(crowd, ",") + `}}`} {
		if _, err := load(raw); err == nil {
			t.Errorf("%s loaded", raw)
		}
	}
	m, err := load(`{"sessions":{"hash":null}}`)
	if err != nil {
		t.Fatal(err)
	}
	m.findKey("any")
	if len(m.st.Sessions) != 0 {
		t.Fatal("a null session was kept")
	}
}

// F13: a person from before keys, holding * on paper only, is no
// administrator: the last one who can sign in keeps *.
func TestAPersonWithoutAKeyIsNoAdministrator(t *testing.T) {
	m, _, token := reviewFixture(t)
	m.st.Users["legacy"] = &User{Grants: []string{"*"}}
	if _, _, err := reviewCall(m, "MONOWEB.owner", "STOP", "GRANT", token, "owner", "*"); code(err) != monolink.CodeState {
		t.Fatalf("the last usable * was taken: %v", err)
	}
}

// F14: one public key is one person's, whatever id it is offered under.
func TestOneKeyIsOnePersons(t *testing.T) {
	m, key, token := reviewFixture(t)
	alias := key.cred
	alias.ID = strings.Repeat("A", 43)
	iv := reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", token, "guest")[0]
	if _, _, err := reviewCall(m, "MONOWEB", "AUTH", "REDEEM", reg(iv, "guest", alias, key.answer(t, m, "MONOWEB", "guest"))...); err == nil {
		t.Fatal("a panel key was taken under an id not its own")
	}
	pass := newPasskey(t, "phone")
	reviewOK(t, m, "MONOWEB", "AUTH", "REDEEM", reg(iv, "guest", pass.cred, pass.answer(t, m, "MONOWEB"))...)
	again := pass.cred
	again.ID = strings.Repeat("B", 43)
	iv2 := reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", token, "olga")[0]
	if _, _, err := reviewCall(m, "MONOWEB", "AUTH", "REDEEM", reg(iv2, "olga", again, pass.answer(t, m, "MONOWEB"))...); code(err) != monolink.CodeState {
		t.Fatalf("one passkey given to a second person: %v", err)
	}
}

// W02: an owner who holds no token for a session taken can still end it:
// every session, invitation and ticket of a person's, in one step.
func TestSignOutEverywhere(t *testing.T) {
	m, key, token := reviewFixture(t)
	if _, _, err := m.openSession("owner", "MONOVIEW", key.cred.Ref(), "", m.now()); err != nil {
		t.Fatal(err)
	}
	iv := reviewOK(t, m, "MONOWEB.owner", "NEW", "INVITE", token, "owner")[0]
	reviewOK(t, m, "MONOWEB.owner", "STOP", "SESSIONS", token, "owner")
	if len(m.st.Sessions) != 0 {
		t.Fatalf("%d sessions still open", len(m.st.Sessions))
	}
	if _, ok := m.st.Ending["owner"]; !ok {
		t.Fatal("their tickets were not ended")
	}
	k := newPanelKey(t)
	if _, _, err := reviewCall(m, "MONOWEB", "AUTH", "REDEEM", reg(iv, "owner", k.cred, k.answer(t, m, "MONOWEB", "owner"))...); err == nil {
		t.Fatal("an invitation outlived signing out everywhere")
	}
}

// W10: a sender from another bubble is no panel of this one's.
func TestAnotherBubblesSenderIsRefused(t *testing.T) {
	m, _, _ := reviewFixture(t)
	if _, _, err := reviewCall(m, "dom/MONOWEB", "AUTH", "CHALLENGE"); code(err) != monolink.CodeDenied {
		t.Fatalf("another bubble's sender: %v", err)
	}
}
