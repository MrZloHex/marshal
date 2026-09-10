package marshal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// State is everything marshal keeps (SPEC §41): people with their grants,
// and open sessions, so a restart does not sign the household out.
//
// Session tokens are kept only as hashes. Whoever reads this file learns
// who is signed in where, and gains no session by it.
type State struct {
	// Secret keys the stand-in challenges answered for names that do not
	// exist, so that they look the same every time they are asked for.
	Secret   string              `json:"secret"`
	Users    map[string]*User    `json:"users"`
	Sessions map[string]*Session `json:"sessions"` // by SHA-256 of the token, hex
}

// User is one person.
type User struct {
	KDF      string    `json:"kdf"`      // how the verifier was derived
	Verifier string    `json:"verifier"` // argon2id of their secret, never the secret
	Grants   []string  `json:"grants"`
	Created  time.Time `json:"created"`
}

// Session is one person signed in at one panel.
type Session struct {
	User    string    `json:"user"`
	Panel   string    `json:"panel"`
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
	if st.Secret == "" {
		sec := make([]byte, 32)
		if _, err := rand.Read(sec); err != nil {
			return nil, err
		}
		st.Secret = hex.EncodeToString(sec)
	}
	return st, nil
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
	return nil
}
