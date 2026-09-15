package marshal

// A browser signed in by a device that already is — SPEC.txt §24, "A
// BROWSER APPROVED", from PROPOSAL_LINK.txt. A browser with nowhere to keep
// a passkey (Firefox on Linux) makes a key it cannot export and asks; the
// person, signed in on their phone or at monoview, reads the code it shows
// and approves; the browser collects a session as them, bound to its key.
// It holds a session and nothing else: no key is added to the account, and
// nothing it does outlasts it.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	log "log/slog"
	"math/big"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/MrZloHex/monolink"
	auth "github.com/MrZloHex/monolink/marshal"
)

const (
	linkTTL     = 2 * time.Minute // how long a code may wait for approval
	linkCollect = time.Minute     // after approval, how long its browser has to collect
	linkMaxAge  = 12 * time.Hour  // an approved browser's session, however faithfully renewed
	maxLinks    = 64              // waiting at once, per panel: every browser is MONOWEB
	maxLinksAt  = 4               // of those, from one place, in portal's word
)

// link is a browser waiting for a device to approve it. It lives in memory
// only: a restart voids it, and no browser is the worse for asking again.
type link struct {
	panel   string           // the panel that asked, and the only one that may collect
	key     *ecdsa.PublicKey // the browser's, which it cannot export
	spki    string           // the same, as it was given
	label   string           // what the browser calls itself: its own word
	from    string           // where it asked from: portal's word
	code    string           // as shown on the browser's screen
	asked   time.Time
	expires time.Time

	// Set when approved: the person, the key their session was opened with,
	// and their key generation then. A key of theirs removed, or their
	// sessions ended everywhere, before the browser collects withdraws it.
	by    string
	byKey string
	byGen int
}

// linkMessage is what a browser's key signs: a purpose, what it answers
// for, and marshal's challenge.
func linkMessage(purpose, what, nonce string) []byte {
	return []byte(purpose + "\x00" + what + "\x00" + nonce)
}

// parseLinkKey reads a browser's key: P-256, SubjectPublicKeyInfo, base64url.
func parseLinkKey(s string) (*ecdsa.PublicKey, error) {
	bad := monolink.Fail(monolink.CodeArg, "a browser's key is P-256, SubjectPublicKeyInfo, base64url")
	der, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(der) > 200 {
		return nil, bad
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	k, ok := pub.(*ecdsa.PublicKey)
	if err != nil || !ok || k.Curve != elliptic.P256() {
		return nil, bad
	}
	return k, nil
}

func validLinkKey(s string) bool {
	_, err := parseLinkKey(s)
	return err == nil
}

// verifyLinkSig checks sig — r‖s, 64 bytes, base64url, as WebCrypto signs
// with ECDSA — by key over msg.
func verifyLinkSig(key *ecdsa.PublicKey, msg []byte, sig string) bool {
	b, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(b) != 64 {
		return false
	}
	h := sha256.Sum256(msg)
	return ecdsa.Verify(key, h[:], new(big.Int).SetBytes(b[:32]), new(big.Int).SetBytes(b[32:]))
}

// newLinkCode is 40 random bits as XXXX-XXXX in Crockford's base32: typed on
// the approving device, as an invitation's code is, and as forgiving.
func newLinkCode() string {
	var s strings.Builder
	for i, x := range random(8) {
		if i == 4 {
			s.WriteByte('-')
		}
		s.WriteByte(crockford[x&31])
	}
	return s.String()
}

// validFrom is where a request came from, as portal writes it: printable,
// and short.
func validFrom(s string) bool {
	if s == "" || len(s) > 64 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// sweepLinks forgets the links whose time is up.
func (m *Marshal) sweepLinks(now time.Time) {
	for h, l := range m.links {
		if !now.Before(l.expires) {
			m.dropLink(h)
		}
	}
}

func (m *Marshal) dropLink(h string) {
	if l := m.links[h]; l != nil {
		delete(m.linkCodes, hashCode(l.code))
	}
	delete(m.links, h)
}

// askLink files a browser's request: its key, its label, and — written by
// portal, over whatever the browser put there — where it asked from. The
// secret goes to the browser alone; the code is for its screen.
func (m *Marshal) askLink(panel string, a []string, now time.Time) (string, []string, error) {
	if len(a) == 2 {
		a = append(a, panel) // not through portal: it is where it is
	}
	key, err := parseLinkKey(a[0])
	if err != nil {
		return "", nil, err
	}
	if !auth.ValidLabel(a[1]) {
		return "", nil, monolink.Fail(monolink.CodeArg, "a label is at most 48 bytes of printable text, without : | or %")
	}
	if !validFrom(a[2]) {
		return "", nil, monolink.Fail(monolink.CodeArg, "not where a request comes from")
	}
	// Bounded per place, not only per panel: every browser is MONOWEB, and a
	// few addresses on the internet must not fill the room for everyone.
	waiting, here := 0, 0
	for _, l := range m.links {
		if l.panel == panel {
			waiting++
			if l.from == a[2] {
				here++
			}
		}
	}
	if waiting >= maxLinks {
		return "", nil, monolink.Fail(monolink.CodeBusy, "too many sign-ins waiting at once")
	}
	if here >= maxLinksAt {
		return "", nil, monolink.Fail(monolink.CodeBusy, "too many sign-ins waiting from there")
	}
	code := newLinkCode()
	for m.linkCodes[hashCode(code)] != "" {
		code = newLinkCode()
	}
	secret := randB64(32)
	h := hashToken(secret)
	l := &link{panel: panel, key: key, spki: a[0], label: a[1], from: a[2], code: code,
		asked: now, expires: now.Add(linkTTL)}
	m.links[h] = l
	m.linkCodes[hashCode(code)] = h
	log.Info("LINK ASKED", "panel", panel, "from", l.from)
	return "LINK", []string{secret, code, l.expires.Format(time.RFC3339)}, nil
}

// linked answers the browser that asked: with its secret alone, whether it
// is approved yet; with its key's answer to a challenge of its panel's as
// well, the session.
func (m *Marshal) linked(panel string, a []string, now time.Time) (string, []string, error) {
	if len(a) == 2 {
		return "", nil, monolink.Fail(monolink.CodeArgc, "AUTH:LINKED takes a secret, or a secret, a challenge and its signature")
	}
	h := hashToken(a[0])
	l := m.links[h]
	if l == nil || l.panel != panel || !now.Before(l.expires) {
		return "", nil, monolink.Fail(monolink.CodeNAC, "no sign-in waiting: it ended, or was refused")
	}
	if len(a) == 1 {
		if l.by == "" {
			return "LINKED", []string{"WAITING"}, nil
		}
		return "LINKED", []string{"READY"}, nil
	}
	answered := m.answered(panel, a[1], now) // spent, right or wrong
	if l.by == "" {
		return "", nil, monolink.Fail(monolink.CodeState, "not approved yet")
	}
	if !answered || !verifyLinkSig(l.key, linkMessage("monolith-link", a[0], a[1]), a[2]) {
		return "", nil, monolink.Fail(monolink.CodeDenied, "")
	}
	if u := m.st.Users[l.by]; u == nil || u.Gen != l.byGen || !m.st.hasKey(l.by, l.byKey) {
		m.dropLink(h)
		return "", nil, monolink.Fail(monolink.CodeNAC, "the approval was withdrawn")
	}
	noun, out, err := m.openSession(l.by, panel, l.byKey, l.spki, now)
	if err != nil {
		return "", nil, err
	}
	m.dropLink(h)
	log.Info("LINK SIGNED IN", "user", l.by, "panel", panel, "key", l.byKey, "from", l.from)
	return noun, out, nil
}

// pending is the link a code names, for who looking from panel. A code that
// is no waiting sign-in's counts as a wrong code does; a right one is never
// refused for wrong ones before it.
func (m *Marshal) pending(panel, who, code string, now time.Time) (*link, string, error) {
	h := m.linkCodes[hashCode(code)]
	l := m.links[h]
	if l == nil || !now.Before(l.expires) {
		return nil, "", m.wrongCode("link "+panel+"/"+who, now)
	}
	return l, h, nil
}

// linkInfo is what a person is asked to approve: the code, the panel that
// asked, when, where from in portal's word, and the browser's own label.
func (m *Marshal) linkInfo(panel, who, code string, now time.Time) (string, []string, error) {
	l, _, err := m.pending(panel, who, code, now)
	if err != nil {
		return "", nil, err
	}
	return "LINK", []string{monolink.Record(l.code, l.panel, l.asked.Format(time.RFC3339), l.from, l.label)}, nil
}

// approveLink lets the browser a code names collect a session as who,
// opened through the key of the session approving it.
func (m *Marshal) approveLink(panel, who string, s *Session, code string, now time.Time) (string, []string, error) {
	l, _, err := m.pending(panel, who, code, now)
	if err != nil {
		return "", nil, err
	}
	if l.by != "" {
		return "", nil, monolink.Fail(monolink.CodeState, "approved already")
	}
	u := m.st.Users[who]
	if s == nil || s.Bound != "" || u == nil {
		return "", nil, monolink.Fail(monolink.CodeDenied, "a sign-in is approved from a session opened with a key")
	}
	l.by, l.byKey, l.byGen = who, s.Key, u.Gen
	if e := now.Add(linkCollect); e.After(l.expires) {
		l.expires = e
	}
	log.Info("LINK APPROVED", "user", who, "at", panel, "for", l.panel, "from", l.from)
	return "LINK", []string{l.code}, nil
}

// refuseLink voids the sign-in a code names: its browser's next question
// finds nothing.
func (m *Marshal) refuseLink(panel, who, code string, now time.Time) (string, []string, error) {
	l, h, err := m.pending(panel, who, code, now)
	if err != nil {
		return "", nil, err
	}
	m.dropLink(h)
	log.Info("LINK REFUSED", "user", who, "at", panel, "for", l.panel, "from", l.from)
	return "LINK", []string{l.code}, nil
}

// resumeProof is what taking up a session again needs besides its token: for
// a browser another device approved, its key's signature over a challenge of
// the panel's. A token copied out of the tab, or out of portal, is worth
// nothing without the key the browser cannot export.
func (m *Marshal) resumeProof(panel, token string, s *Session, proof []string, now time.Time) error {
	if s.Bound == "" {
		if len(proof) > 0 {
			return monolink.Fail(monolink.CodeArgc, "SET:SESSION takes a token")
		}
		return nil
	}
	if len(proof) != 2 {
		return monolink.Fail(monolink.CodeDenied, "this browser's session is taken up again only with its key")
	}
	key, err := parseLinkKey(s.Bound)
	answered := m.answered(panel, proof[0], now)
	if err != nil || !answered || !verifyLinkSig(key, linkMessage("monolith-resume", token, proof[0]), proof[1]) {
		return monolink.Fail(monolink.CodeDenied, "")
	}
	return nil
}
