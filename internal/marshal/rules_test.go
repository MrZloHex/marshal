package marshal

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/MrZloHex/monolink"
	auth "github.com/MrZloHex/monolink/marshal"
)

// setNow moves marshal's clock, as its own goroutines read it.
func setNow(m *Marshal, t time.Time) {
	m.mu.Lock()
	m.now = func() time.Time { return t }
	m.mu.Unlock()
}

// An invitation for someone new is not a key for whoever has the name by the
// time it is used; and it is worth no more than its maker's grants are then.
func TestAnInvitationIsJudgedAgainWhenTakenUp(t *testing.T) {
	b, _, mv, s := enrolled(t)
	ctx := tctx(t)
	web, _, ds := invited(t, b, mv, s.Token, "dasha")
	if err := auth.Grant(ctx, mv, s.Token, "dasha", "MARSHAL.NEW.INVITE"); err != nil {
		t.Fatal(err)
	}
	forOlga, _, err := auth.Invite(ctx, web, ds.Token, "olga")
	if err != nil {
		t.Fatal(err)
	}
	invited(t, b, mv, s.Token, "olga") // the real olga, meanwhile
	if _, err := newPasskey(t, "").redeem(t, b.panel(t, "MONOWEB"), forOlga, "olga"); code(err) != monolink.CodeState {
		t.Fatalf("dasha's invitation for someone new became a key to olga: %v", err)
	}

	forPavel, _, err := auth.Invite(ctx, web, ds.Token, "pavel")
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.Revoke(ctx, mv, s.Token, "dasha", "MARSHAL.NEW.INVITE"); err != nil {
		t.Fatal(err)
	}
	if _, err := newPasskey(t, "").redeem(t, b.panel(t, "MONOWEB"), forPavel, "pavel"); code(err) != monolink.CodeDenied {
		t.Fatalf("an invitation outlived its maker's grant: %v", err)
	}
}

// Other nodes know people by name: someone new must not inherit a removed
// person's messages by being given their name.
func TestARemovedPersonsNameIsNotGivenAgain(t *testing.T) {
	b, _, mv, s := enrolled(t)
	ctx := tctx(t)
	invited(t, b, mv, s.Token, "dasha")
	if err := auth.RemoveUser(ctx, mv, s.Token, "dasha"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.Invite(ctx, mv, s.Token, "dasha"); code(err) != monolink.CodeState {
		t.Fatalf("a removed person's name was offered again: %v", err)
	}
}

// MARSHAL.SET.GRANT is not a way to become *: a person hands on what their
// grants cover, and changes nobody who may do more than they may.
func TestNobodyGrantsMoreThanTheyHold(t *testing.T) {
	b, _, mv, s := enrolled(t)
	ctx := tctx(t)
	web, _, ds := invited(t, b, mv, s.Token, "dasha")
	invited(t, b, mv, s.Token, "olga")
	for _, g := range []string{"MARSHAL.SET.GRANT", "MARSHAL.STOP.GRANT", "VERTEX.*"} {
		if err := auth.Grant(ctx, mv, s.Token, "dasha", g); err != nil {
			t.Fatal(err)
		}
	}
	if err := auth.Grant(ctx, web, ds.Token, "olga", "VERTEX.SET.LED.BRIGHT"); err != nil {
		t.Fatalf("a grant within dasha's own: %v", err)
	}
	for _, g := range []struct{ who, pattern string }{{"olga", "UKAZ.*"}, {"dasha", "MARSHAL.*"}, {"olga", "*"}} {
		if err := auth.Grant(ctx, web, ds.Token, g.who, g.pattern); code(err) != monolink.CodeDenied {
			t.Errorf("dasha granted %s %s: %v", g.who, g.pattern, err)
		}
	}
	if err := auth.Revoke(ctx, web, ds.Token, "mzh", "*"); code(err) != monolink.CodeDenied {
		t.Fatalf("dasha took * from mzh: %v", err)
	}
}

// A new key must not come of a session someone left open, or took — nor of
// a fresh sign-in that was another session's: the old one is no fresher for
// it (review_test.go has every change; this is the way panels ask).
func TestANewKeyNeedsItsSessionFresh(t *testing.T) {
	b := newBus(t)
	m, _ := startMarshal(t, b, filepath.Join(t.TempDir(), "marshal.json"))
	mv := b.panel(t, "MONOVIEW")
	key := newPanelKey(t)
	old, err := key.enrol(t, mv, m.EnrolCode(), "mzh")
	if err != nil {
		t.Fatal(err)
	}
	mv.SetActor("mzh")
	setNow(m, time.Now().Add(freshSignIn+time.Minute))
	if _, _, err := auth.Invite(tctx(t), mv, old.Token, "mzh"); code(err) != monolink.CodeDenied {
		t.Fatalf("an invitation from a sign-in long past: %v", err)
	}
	fresh, err := key.signIn(t, mv, "mzh")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.Invite(tctx(t), mv, old.Token, "mzh"); code(err) != monolink.CodeDenied {
		t.Fatalf("the old session took the new one's sign-in for its own: %v", err)
	}
	if _, _, err := auth.Invite(tctx(t), mv, fresh.Token, "mzh"); err != nil {
		t.Fatalf("an invitation just after signing in: %v", err)
	}
	if n, err := auth.SignOutEverywhere(tctx(t), mv, old.Token, "mzh"); err != nil || n != 2 {
		t.Fatalf("signing oneself out everywhere, from the old session: %d, %v", n, err)
	}
}

// Every browser on the internet is MONOWEB. A stranger guessing codes there
// locks MONOWEB's codes, not enrolment at home; and wrong codes are
// forgotten after a quiet hour, so they never add up to a lockout for good.
func TestGuessingLocksOnlyItsOwnPanelAndIsForgotten(t *testing.T) {
	b := newBus(t)
	m, _ := startMarshal(t, b, filepath.Join(t.TempDir(), "marshal.json"))
	web := b.panel(t, "MONOWEB")
	guess := func() error {
		_, err := newPasskey(t, "").redeem(t, web, "0000-0000-0000", "eve")
		return err
	}
	for range freeFailures {
		guess()
	}
	if err := guess(); code(err) != monolink.CodeBusy {
		t.Fatalf("guessing went on unlocked: %v", err)
	}

	setNow(m, time.Now().Add(maxLockout+forgetFailures+time.Minute))
	for i := range freeFailures - 1 {
		if err := guess(); code(err) != monolink.CodeDenied {
			t.Fatalf("guess %d after a quiet hour: %v", i, err)
		}
	}

	mv := b.panel(t, "MONOVIEW")
	if _, err := newPanelKey(t).enrol(t, mv, m.EnrolCode(), "mzh"); err != nil {
		t.Fatalf("home enrolment locked by a stranger's guesses: %v", err)
	}
}
