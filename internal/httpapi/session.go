package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
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
	cookieCSRF       = "ah_csrf"
	csrfField        = "csrf"
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

func randomHex() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (st *sessionStore) issue() (string, error) {
	id, err := randomHex()
	if err != nil {
		return "", err
	}
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
	mu        sync.Mutex
	fail      map[string][]time.Time
	lastSweep time.Time
}

type limitKey struct {
	key string
	max int
}

func newLoginLimit() *loginLimit {
	return &loginLimit{fail: make(map[string][]time.Time), lastSweep: time.Now()}
}

func (l *loginLimit) begin(ip string) bool {
	return l.reserve(limitKey{ip, loginMaxFail})
}

// reserve counts an attempt against every key, or against none if any key is at
// its limit. Counting before the password check stops concurrent guesses from
// passing the limit together.
func (l *loginLimit) reserve(keys ...limitKey) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := time.Now(); now.Sub(l.lastSweep) > loginWindow {
		l.lastSweep = now
		for k := range l.fail {
			l.prune(k)
		}
	}
	for _, k := range keys {
		if len(l.prune(k.key)) >= k.max {
			return false
		}
	}
	now := time.Now()
	for _, k := range keys {
		l.fail[k.key] = append(l.fail[k.key], now)
	}
	return true
}

func (l *loginLimit) clear(key string) {
	l.mu.Lock()
	delete(l.fail, key)
	l.mu.Unlock()
}

// refund takes back one attempt, for a key that other clients share.
func (l *loginLimit) refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n := len(l.fail[key]); n > 1 {
		l.fail[key] = l.fail[key][:n-1]
	} else {
		delete(l.fail, key)
	}
}

func (l *loginLimit) prune(key string) []time.Time {
	cut := time.Now().Add(-loginWindow)
	var keep []time.Time
	for _, t := range l.fail[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fail, key)
	} else {
		l.fail[key] = keep
	}
	return keep
}

// hostCookieName adds the __Host- prefix on HTTPS. Browsers refuse a __Host-
// cookie set from a subdomain or over HTTP, so content hosts cannot plant one.
// Reading only this name means an unprefixed cookie is ignored on HTTPS.
func hostCookieName(r *http.Request, base string) string {
	if forwardedHTTPS(r) {
		return "__Host-" + base
	}
	return base
}

func csrfCookie(r *http.Request, val string) *http.Cookie {
	return &http.Cookie{
		Name:     hostCookieName(r, cookieCSRF),
		Value:    val,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   forwardedHTTPS(r),
	}
}

// ensureCSRF returns the token for forms on this page, keeping any existing one
// so that forms in other open tabs stay valid.
func ensureCSRF(w http.ResponseWriter, r *http.Request) (string, error) {
	var tok string
	if c, err := r.Cookie(hostCookieName(r, cookieCSRF)); err == nil {
		tok = c.Value
	}
	if tok == "" {
		var err error
		if tok, err = randomHex(); err != nil {
			return "", err
		}
	}
	http.SetCookie(w, csrfCookie(r, tok))
	return tok, nil
}

func csrfOK(r *http.Request) bool {
	return originMatches(r) && csrfTokenOK(r)
}

// csrfOKAllowNullOrigin is for a form on a page with Referrer-Policy: no-referrer.
// Browsers send "Origin: null" for that form, so only the token can vouch for it.
func csrfOKAllowNullOrigin(r *http.Request) bool {
	return (r.Header.Get("Origin") == "null" || originMatches(r)) && csrfTokenOK(r)
}

func originMatches(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	return origin == "" || strings.EqualFold(origin, requestOrigin(r))
}

func csrfTokenOK(r *http.Request) bool {
	c, err := r.Cookie(hostCookieName(r, cookieCSRF))
	if err != nil || c.Value == "" {
		return false
	}
	// ParseForm reads urlencoded bodies only, so this needs no multipart parsing
	// before authentication. PostForm excludes the URL query.
	_ = r.ParseForm()
	return subtle.ConstantTimeCompare([]byte(r.PostForm.Get(csrfField)), []byte(c.Value)) == 1
}

func requestOrigin(r *http.Request) string {
	if forwardedHTTPS(r) {
		return "https://" + r.Host
	}
	return "http://" + r.Host
}

// csrfProtect guards handlers that browsers can reach with ambient cookies. A
// bearer token is never sent automatically, so a bearer request needs no check.
func (s *Server) csrfProtect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.adminOK(r) && !csrfOK(r) {
			http.Error(w, "CSRF check failed. Reload the page and try again.", http.StatusForbidden)
			return
		}
		next(w, r)
	}
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
