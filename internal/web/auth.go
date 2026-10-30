package web

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	hashScheme     = "pbkdf2-sha256"
	hashIterations = 600_000
	sessionTTL     = 12 * time.Hour
	sessionCookie  = "wanhound_session"

	// Login throttling: per client address, and globally so a
	// distributed guesser gains nothing from many source addresses.
	failWindow    = 15 * time.Minute
	failsPerIP    = 5
	failsGlobal   = 30
	failureDelay  = 750 * time.Millisecond
	maxSessions   = 64
	trackedIPsMax = 4096
)

// HashPassword returns "pbkdf2-sha256$<iter>$<salt>$<key>" for
// WANHOUND_PASSWORD_HASH, so the plaintext need not live in the
// service's environment.
func HashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key, _ := pbkdf2.Key(sha256.New, pw, salt, hashIterations, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s", hashScheme, hashIterations, enc.EncodeToString(salt), enc.EncodeToString(key))
}

type passwordHash struct {
	iter      int
	salt, key []byte
}

func parseHash(s string) (*passwordHash, error) {
	parts := strings.Split(s, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return nil, fmt.Errorf("password hash must look like %s$<iterations>$<salt>$<key> (see `wanhound hash-password`)", hashScheme)
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 100_000 {
		return nil, fmt.Errorf("password hash: iteration count must be at least 100000")
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	key, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(key) < 16 {
		return nil, fmt.Errorf("password hash: malformed salt or key")
	}
	return &passwordHash{iter: iter, salt: salt, key: key}, nil
}

func (h *passwordHash) verify(pw string) bool {
	key, err := pbkdf2.Key(sha256.New, pw, h.salt, h.iter, len(h.key))
	return err == nil && hmac.Equal(key, h.key)
}

// sessions is an in-memory session table; a restart logs everyone out.
type sessions struct {
	mu sync.Mutex
	m  map[string]time.Time // token -> expiry
}

func newSessions() *sessions { return &sessions{m: map[string]time.Time{}} }

func (s *sessions) create() string {
	b := make([]byte, 32)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for t, exp := range s.m {
		if now.After(exp) {
			delete(s.m, t)
		}
	}
	if len(s.m) >= maxSessions { // drop the oldest
		var oldest string
		for t, exp := range s.m {
			if oldest == "" || exp.Before(s.m[oldest]) {
				oldest = t
			}
		}
		delete(s.m, oldest)
	}
	s.m[tok] = now.Add(sessionTTL)
	return tok
}

func (s *sessions) valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[tok]
	if ok && time.Now().After(exp) {
		delete(s.m, tok)
		return false
	}
	return ok
}

func (s *sessions) revoke(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// limiter tracks failed logins.
type limiter struct {
	mu     sync.Mutex
	perIP  map[string][]time.Time
	global []time.Time
}

func newLimiter() *limiter { return &limiter{perIP: map[string][]time.Time{}} }

func prune(ts []time.Time, now time.Time) []time.Time {
	i := 0
	for i < len(ts) && now.Sub(ts[i]) > failWindow {
		i++
	}
	return ts[i:]
}

// blocked reports whether ip may not attempt a login now, and for how long.
func (l *limiter) blocked(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.global = prune(l.global, now)
	l.perIP[ip] = prune(l.perIP[ip], now)
	if ts := l.perIP[ip]; len(ts) >= failsPerIP {
		return true, failWindow - now.Sub(ts[0])
	}
	if len(l.global) >= failsGlobal {
		return true, failWindow - now.Sub(l.global[0])
	}
	return false, 0
}

func (l *limiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.perIP) >= trackedIPsMax {
		for k, ts := range l.perIP {
			if len(prune(ts, now)) == 0 {
				delete(l.perIP, k)
			}
		}
	}
	l.perIP[ip] = append(l.perIP[ip], now)
	l.global = append(l.global, now)
}

func (l *limiter) success(ip string) {
	l.mu.Lock()
	delete(l.perIP, ip)
	l.mu.Unlock()
}
