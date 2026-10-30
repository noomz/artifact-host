package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	minAdminTokenLen = 32
	loginWindow      = 15 * time.Minute
	loginMaxFail     = 5
	sessionTTL       = 14 * 24 * time.Hour
	cookieSession    = "ah_session"
)

func ValidateAdminToken(s string) error {
	if s == "" {
		return errors.New("ARTIFACT_HOST_ADMIN_TOKEN is required")
	}
	if len(s) < minAdminTokenLen {
		return errors.New("ARTIFACT_HOST_ADMIN_TOKEN must be at least 32 characters")
	}
	switch strings.ToLower(s) {
	case "replace-me", "change-me", "changeme", "password", "admin", "secret":
		return errors.New("ARTIFACT_HOST_ADMIN_TOKEN is a placeholder")
	}
	return nil
}

type sessionStore struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{m: make(map[string]time.Time)}
}

func (st *sessionStore) issue() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	st.mu.Lock()
	st.m[id] = time.Now().Add(sessionTTL)
	st.mu.Unlock()
	return id, nil
}

func (st *sessionStore) valid(id string) bool {
	if id == "" {
		return false
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	exp, ok := st.m[id]
	if !ok || time.Now().After(exp) {
		delete(st.m, id)
		return false
	}
	return true
}

func (st *sessionStore) revoke(id string) {
	st.mu.Lock()
	delete(st.m, id)
	st.mu.Unlock()
}

type loginLimit struct {
	mu   sync.Mutex
	fail map[string][]time.Time
}

func newLoginLimit() *loginLimit {
	return &loginLimit{fail: make(map[string][]time.Time)}
}

func (l *loginLimit) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	keep := l.prune(ip)
	return len(keep) < loginMaxFail
}

func (l *loginLimit) record(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	keep := l.prune(ip)
	l.fail[ip] = append(keep, time.Now())
}

func (l *loginLimit) clear(ip string) {
	l.mu.Lock()
	delete(l.fail, ip)
	l.mu.Unlock()
}

func (l *loginLimit) prune(ip string) []time.Time {
	cut := time.Now().Add(-loginWindow)
	var keep []time.Time
	for _, t := range l.fail[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fail, ip)
	} else {
		l.fail[ip] = keep
	}
	return keep
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
