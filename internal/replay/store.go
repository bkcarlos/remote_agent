package replay

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var ErrAlreadyUsed = errors.New("nonce or token was already used")

type Store interface {
	Consume(namespace, id string, expiresAt, now time.Time) error
}

type ChallengeStore interface {
	Store
	Put(namespace, id string, payload []byte, expiresAt time.Time) error
	Take(namespace, id string, now time.Time) ([]byte, error)
}

var ErrNotFound = errors.New("challenge was not found or expired")

type memoryChallenge struct {
	payload []byte
	expires time.Time
}
type Memory struct {
	mu         sync.Mutex
	used       map[string]time.Time
	challenges map[string]memoryChallenge
}

func NewMemory() *Memory {
	return &Memory{used: map[string]time.Time{}, challenges: map[string]memoryChallenge{}}
}
func (m *Memory) Consume(namespace, id string, expiresAt, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := namespace + "\x00" + id
	if expiry, exists := m.used[key]; exists && expiry.After(now) {
		return ErrAlreadyUsed
	}
	for key, expiry := range m.used {
		if !expiry.After(now) {
			delete(m.used, key)
		}
	}
	m.used[key] = expiresAt
	return nil
}

func (m *Memory) Put(namespace, id string, payload []byte, expiresAt time.Time) error {
	if namespace == "" || id == "" || len(payload) == 0 {
		return errors.New("invalid challenge")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := namespace + "\x00" + id
	if current, exists := m.challenges[key]; exists && current.expires.After(time.Now()) {
		return ErrAlreadyUsed
	}
	m.challenges[key] = memoryChallenge{payload: append([]byte(nil), payload...), expires: expiresAt}
	return nil
}
func (m *Memory) Take(namespace, id string, now time.Time) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := namespace + "\x00" + id
	entry, exists := m.challenges[key]
	if !exists || !entry.expires.After(now) {
		delete(m.challenges, key)
		return nil, ErrNotFound
	}
	delete(m.challenges, key)
	return append([]byte(nil), entry.payload...), nil
}

type Bolt struct{ db *bolt.DB }

func OpenBolt(path string) (*Bolt, error) {
	if path == "" {
		return nil, errors.New("replay database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, NoSync: false})
	if err != nil {
		return nil, err
	}
	return &Bolt{db: db}, nil
}
func (s *Bolt) Close() error { return s.db.Close() }
func (s *Bolt) Put(namespace, id string, payload []byte, expiresAt time.Time) error {
	if namespace == "" || id == "" || len(payload) == 0 || expiresAt.IsZero() {
		return errors.New("invalid challenge")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("challenge:" + namespace))
		if err != nil {
			return err
		}
		key := []byte(id)
		if current := bucket.Get(key); len(current) >= 8 && time.Unix(0, int64(binary.BigEndian.Uint64(current[:8]))).After(time.Now()) {
			return ErrAlreadyUsed
		}
		value := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint64(value[:8], uint64(expiresAt.UnixNano()))
		copy(value[8:], payload)
		return bucket.Put(key, value)
	})
}
func (s *Bolt) Take(namespace, id string, now time.Time) ([]byte, error) {
	var payload []byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("challenge:" + namespace))
		if bucket == nil {
			return ErrNotFound
		}
		value := bucket.Get([]byte(id))
		if len(value) < 9 || !time.Unix(0, int64(binary.BigEndian.Uint64(value[:8]))).After(now) {
			_ = bucket.Delete([]byte(id))
			return ErrNotFound
		}
		payload = append([]byte(nil), value[8:]...)
		return bucket.Delete([]byte(id))
	})
	return payload, err
}

func (s *Bolt) Consume(namespace, id string, expiresAt, now time.Time) error {
	if namespace == "" || id == "" || !expiresAt.After(now) {
		return errors.New("invalid replay entry")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(namespace))
		if err != nil {
			return err
		}
		key := []byte(id)
		if raw := bucket.Get(key); len(raw) == 8 {
			existing := int64(binary.BigEndian.Uint64(raw))
			if time.Unix(0, existing).After(now) {
				return ErrAlreadyUsed
			}
		}
		var value [8]byte
		binary.BigEndian.PutUint64(value[:], uint64(expiresAt.UnixNano()))
		if err := bucket.Put(key, value[:]); err != nil {
			return err
		}
		// Opportunistically remove a bounded number of expired records.
		cursor := bucket.Cursor()
		removed := 0
		for k, v := cursor.First(); k != nil && removed < 128; k, v = cursor.Next() {
			if len(v) == 8 && !time.Unix(0, int64(binary.BigEndian.Uint64(v))).After(now) {
				if err := cursor.Delete(); err != nil {
					return err
				}
				removed++
			}
		}
		return nil
	})
}
