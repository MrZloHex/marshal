package marshal

import (
	"encoding/json"
	"errors"
	"fmt"
	log "log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/MrZloHex/monolink"
	auth "github.com/MrZloHex/monolink/marshal"
)

// State is everything marshal keeps (SPEC §41): people with their keys and
// grants, and open sessions, so a restart does not sign the household out.
//
// Nothing in it signs anybody in. Keys are public halves; session tokens
// are kept only as hashes. Whoever reads this file learns who is signed in
// where, and gains no session by it.
type State struct {
	Users    map[string]*User    `json:"users"`
	Sessions map[string]*Session `json:"sessions"` // by SHA-256 of the token, hex
	// Retired are the names of people removed. Nobody is given one again:
	// other nodes know people by name, and someone new must not inherit
	// what was the old one's — synapse's history above all.
	Retired []string `json:"retired,omitempty"`
	// Ending are the cutoffs of ended tickets the hub has not yet
	// acknowledged, by person: saved with the change that ended them, so a
	// restart or a hub out of reach loses none.
	Ending map[string]time.Time `json:"ending,omitempty"`
}

// User is one person.
type User struct {
	Keys    []*Key    `json:"keys"`
	Grants  []string  `json:"grants"`
	Created time.Time `json:"created"`
	// Gen counts the keys removed from them, and times they were signed out
	// everywhere: an invitation made before voids with it.
	Gen int `json:"gen,omitempty"`
}

// Key is one of a person's keys: a passkey, or a panel's own.
type Key struct {
	auth.Credential
	Ref   string    `json:"ref"`
	Added time.Time `json:"added"`
}

// Session is one person signed in at one panel, with one of their keys.
type Session struct {
	User    string    `json:"user"`
	Panel   string    `json:"panel"`
	Key     string    `json:"key"` // its Ref
	Since   time.Time `json:"since"`
	Expires time.Time `json:"expires"`
}

// Store reads and writes the state file. The whole state is rewritten on
// each change: a household has a handful of people and sessions.
type Store struct {
	path string
}

func NewStore(path string) *Store { return &Store{path: path} }

// Load reads the state, or starts an empty one if there is no file yet.
//
// A state from before keys loads too: its people keep their grants and lose
// their secrets, and its sessions, which no key opened, are gone.
func (s *Store) Load() (*State, error) {
	st := &State{}
	b, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("read %s: %w", s.path, err)
	default:
		if err := json.Unmarshal(b, st); err != nil {
			return nil, fmt.Errorf("parse %s: %w", s.path, err)
		}
	}
	if st.Users == nil {
		st.Users = map[string]*User{}
	}
	if st.Sessions == nil {
		st.Sessions = map[string]*Session{}
	}
	if st.Ending == nil {
		st.Ending = map[string]time.Time{}
	}
	if err := st.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	return st, nil
}

// check refuses a state that parses but cannot be right — a hand edit, a
// partial restore, a bad merge — rather than crash on it later, and drops
// what is merely stale.
func (st *State) check() error {
	ids := map[string]string{}
	for name, u := range st.Users {
		switch {
		case u == nil:
			return fmt.Errorf("person %q is null", name)
		case !auth.ValidName(name):
			return fmt.Errorf("%q is not a person's name", name)
		case slices.Contains(st.Retired, name):
			return fmt.Errorf("%q is a retired name, yet someone's", name)
		}
		for _, k := range u.Keys {
			if k == nil || k.ID == "" || k.Ref == "" {
				return fmt.Errorf("a key of %q's is empty", name)
			}
			if other, dup := ids[k.ID]; dup {
				return fmt.Errorf("one key is both %q's and %q's", other, name)
			}
			ids[k.ID] = name
		}
		// A grant no longer written as one (a star not after a dot) is
		// dropped, not widened: less may be allowed, never more.
		kept := u.Grants[:0]
		for _, g := range u.Grants {
			if auth.ValidPattern(g) {
				kept = append(kept, g)
			} else {
				log.Warn("GRANT DROPPED: not a grant as written now", "user", name, "grant", g)
			}
		}
		u.Grants = kept
	}
	// A session from before keys, or of a person or key since gone, is no
	// session to keep.
	for h, ss := range st.Sessions {
		if ss == nil || ss.Key == "" || !st.hasKey(ss.User, ss.Key) {
			delete(st.Sessions, h)
		}
	}
	for p := range st.Ending {
		if !auth.ValidName(p) {
			return fmt.Errorf("an ended ticket's person %q is not a name", p)
		}
	}
	// Every name fits GET:USERS and PEOPLE, one frame and one field: past
	// that, PEOPLE would stay stale and GET:USERS go unanswered.
	names := make([]string, 0, len(st.Users))
	for n := range st.Users {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > maxPeople || len(monolink.Escape(monolink.Record(names...))) > monolink.MaxField {
		return fmt.Errorf("%d people, more than one frame can name", len(names))
	}
	return nil
}

func (st *State) hasKey(user, ref string) bool {
	if u := st.Users[user]; u != nil {
		return slices.ContainsFunc(u.Keys, func(k *Key) bool { return k.Ref == ref })
	}
	return false
}

// Save atomically replaces the file. The temp file is created in the same
// directory so the rename cannot cross a filesystem boundary, and
// os.CreateTemp makes it readable by its owner only, which the rename keeps.
func (s *Store) Save(st *State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	b = append(b, '\n')

	dir := filepath.Dir(s.path)
	// The directory is opened first: one that cannot be synced fails the save
	// before anything has changed.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	defer d.Close()
	tmp, err := os.CreateTemp(dir, ".marshal-*")
	if err != nil {
		return fmt.Errorf("temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()

	defer func() {
		// No-op once the rename has succeeded.
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("rename onto %s: %w", s.path, err)
	}
	// Committed: the new file is what any reader now gets. A failed sync of
	// the directory is not a failed save — undoing the change in memory would
	// make memory disagree with the file — but a power cut could still bring
	// the old file back, and that is said loudly.
	if err := d.Sync(); err != nil {
		log.Error("STATE SAVED BUT NOT SYNCED: a power cut could undo the last change", "dir", dir, "err", err)
	}
	return nil
}
