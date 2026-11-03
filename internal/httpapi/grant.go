package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/sites"
)

const (
	grantSessionTTL    = 24 * time.Hour
	grantFailsPerSite  = 100
	grantLoginBodyMax  = 16 << 10
	passwordAPIBodyMax = 64 << 10
)

var (
	tplGrantLogin = template.Must(template.ParseFS(adminFS, "templates/grant_login.html"))
	tplGrantLink  = template.Must(template.ParseFS(adminFS, "templates/grant_link.html"))

	errNoContentDomain = fmt.Errorf("%w: share links need ARTIFACT_HOST_CONTENT_DOMAIN set on the server", domain.ErrInvalid)
)

func (s *Server) setSitePassword(w http.ResponseWriter, r *http.Request) {
	actor, err := s.principal(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Password *string `json:"password"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, passwordAPIBodyMax))
	if err := dec.Decode(&body); err != nil || body.Password == nil {
		writeErr(w, domain.ErrInvalid)
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeErr(w, domain.ErrInvalid)
		return
	}
	if err := s.Host.SetPassword(r.Context(), actor, domain.SiteID(r.PathValue("id")), *body.Password); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) clearSitePassword(w http.ResponseWriter, r *http.Request) {
	actor, err := s.principal(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := s.Host.ClearPassword(r.Context(), actor, domain.SiteID(r.PathValue("id"))); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) grantLoginGET(w http.ResponseWriter, r *http.Request) {
	if _, err := s.contentSite(r); err != nil {
		writeErr(w, err)
		return
	}
	renderGrantLogin(w, r, http.StatusOK, r.URL.Query().Get("next"), "")
}

// grantLoginPOST answers the same way for a wrong password and for a site with
// no password, so the response does not reveal which grants a site has.
func (s *Server) grantLoginPOST(w http.ResponseWriter, r *http.Request) {
	site, err := s.contentSite(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, grantLoginBodyMax)
	if !csrfOK(r) {
		http.Error(w, "CSRF check failed. Reload the page and try again.", http.StatusForbidden)
		return
	}
	siteKey := string(site.ID)
	ipKey := siteKey + "|" + clientIP(r)
	if !s.grantLogins.reserve(limitKey{ipKey, loginMaxFail}, limitKey{siteKey, grantFailsPerSite}) {
		w.Header().Set("Retry-After", strconv.Itoa(int(loginWindow.Seconds())))
		http.Error(w, "Too many attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	next := r.PostForm.Get("next")
	password, err := s.Host.VerifyPassword(r.Context(), site.ID, r.PostForm.Get("password"))
	if errors.Is(err, domain.ErrUnauthorized) {
		renderGrantLogin(w, r, http.StatusUnauthorized, next, "Wrong password.")
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	raw, err := randomHex()
	if err != nil {
		writeErr(w, err)
		return
	}
	now := time.Now()
	session := domain.GrantSession{Site: site.ID, Password: password, ExpiresAt: now.Add(grantSessionTTL)}
	err = s.Host.Meta.CreateGrantSession(r.Context(), session, TokenHash(raw), now)
	if errors.Is(err, domain.ErrNotFound) {
		// The password changed while this login was verifying the old one.
		renderGrantLogin(w, r, http.StatusUnauthorized, next, "Wrong password.")
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	s.grantLogins.clear(ipKey)
	s.grantLogins.refund(siteKey)
	http.SetCookie(w, grantCookie(r, raw, grantSessionTTL))
	http.Redirect(w, r, safeNext(next), http.StatusSeeOther)
}

func (s *Server) createSiteLink(w http.ResponseWriter, r *http.Request) {
	actor, err := s.principal(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	// Without a content host the link has no URL, and its token is shown only once.
	if s.ContentDomain == "" {
		writeErr(w, errNoContentDomain)
		return
	}
	var body struct {
		Label     string `json:"label"`
		ExpiresIn string `json:"expires_in"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, passwordAPIBodyMax))
	if err := dec.Decode(&body); err != nil {
		writeErr(w, domain.ErrInvalid)
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeErr(w, domain.ErrInvalid)
		return
	}
	link, token, err := s.Host.CreateLink(r.Context(), actor, domain.SiteID(r.PathValue("id")), body.Label, body.ExpiresIn)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         link.ID,
		"label":      link.Label,
		"url":        s.contentURL(link.Site) + sites.ReservedDir + "/link/" + token,
		"expires_at": link.ExpiresAt,
	})
}

func (s *Server) revokeSiteLink(w http.ResponseWriter, r *http.Request) {
	actor, err := s.principal(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := s.Host.RevokeLink(r.Context(), actor, domain.SiteID(r.PathValue("id")), domain.LinkID(r.PathValue("link_id"))); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) siteAccess(w http.ResponseWriter, r *http.Request) {
	actor, err := s.principal(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	id := domain.SiteID(r.PathValue("id"))
	access, err := s.Host.Access(r.Context(), actor, id)
	if err != nil {
		writeErr(w, err)
		return
	}
	type linkResult struct {
		ID        domain.LinkID `json:"id"`
		Label     string        `json:"label"`
		CreatedAt time.Time     `json:"created_at"`
		ExpiresAt time.Time     `json:"expires_at"`
	}
	links := make([]linkResult, 0, len(access.Links))
	for _, l := range access.Links {
		links = append(links, linkResult{l.ID, l.Label, l.CreatedAt, l.ExpiresAt})
	}
	contentURL := ""
	if s.ContentDomain != "" {
		contentURL = s.contentURL(id)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"has_password": access.HasPassword,
		"links":        links,
		"content_url":  contentURL,
	})
}

// liveLink writes the response itself when the token is no good. Every failure is
// the same 404, so a request cannot tell invalid, expired, and revoked apart. The
// token is in the URL, so no response from here may send it on as a referrer.
func (s *Server) liveLink(w http.ResponseWriter, r *http.Request) (domain.SiteLink, bool) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	site, err := s.contentSite(r)
	if err != nil {
		writeErr(w, err)
		return domain.SiteLink{}, false
	}
	link, err := s.Host.LinkByToken(r.Context(), site.ID, r.PathValue("token"))
	if err != nil {
		writeErr(w, err)
		return domain.SiteLink{}, false
	}
	return link, true
}

// linkGET creates no session, so a chat app or mail scanner that fetches the link
// does not use it.
func (s *Server) linkGET(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.liveLink(w, r); !ok {
		return
	}
	csrf, err := ensureCSRF(w, r)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tplGrantLink.Execute(w, map[string]string{"CSRF": csrf})
}

func (s *Server) linkPOST(w http.ResponseWriter, r *http.Request) {
	link, ok := s.liveLink(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, grantLoginBodyMax)
	if !csrfOKAllowNullOrigin(r) {
		http.Error(w, "CSRF check failed. Reload the page and try again.", http.StatusForbidden)
		return
	}
	raw, err := randomHex()
	if err != nil {
		writeErr(w, err)
		return
	}
	now := time.Now()
	expires := now.Add(grantSessionTTL)
	if link.ExpiresAt.Before(expires) {
		expires = link.ExpiresAt
	}
	session := domain.GrantSession{Site: link.Site, Link: link.ID, ExpiresAt: expires}
	// ErrNotFound here means the link was revoked during this request, which gets
	// the same 404 as any other dead link.
	if err := s.Host.Meta.CreateGrantSession(r.Context(), session, TokenHash(raw), now); err != nil {
		writeErr(w, err)
		return
	}
	http.SetCookie(w, grantCookie(r, raw, expires.Sub(now)))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func grantCookie(r *http.Request, raw string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     hostCookieName(r, cookieGrant),
		Value:    raw,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   forwardedHTTPS(r),
	}
}

func renderGrantLogin(w http.ResponseWriter, r *http.Request, code int, next, message string) {
	csrf, err := ensureCSRF(w, r)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = tplGrantLogin.Execute(w, map[string]string{"CSRF": csrf, "Next": safeNext(next), "Err": message})
}

// safeNext keeps a login redirect on this host. Browsers treat a backslash as a
// slash and strip tabs and newlines, so "/\evil" and "/\t/evil" both act as
// "//evil", a link to another host.
func safeNext(raw string) string {
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return "/"
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c == '\\' || c < 0x20 || c == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return raw
}
