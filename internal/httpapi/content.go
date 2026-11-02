package httpapi

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/sites"
)

const (
	cookieGrant = "ah_grant"

	// contentCSP stops a published page sending data out through forms, fetch,
	// or remote images. Allowing any script host would leak data through the
	// request URL, so the CDN list is fixed.
	contentCSP = "default-src 'self' data: blob:; " +
		"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com https://esm.sh; " +
		"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
		"font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; " +
		"img-src 'self' data: blob:; " +
		"connect-src 'self'; " +
		"form-action 'none'; " +
		"base-uri 'none'; " +
		"object-src 'none'; " +
		"frame-ancestors 'none'"

	serverPageCSP = "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)

var (
	contentIDPattern     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	contentDomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// ParseContentDomain validates the configured domain. It refuses a domain that
// covers the base URL's host, because that host's admin and API would then be
// routed as content.
func ParseContentDomain(raw, baseURL string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	if d == "" {
		return "", nil
	}
	if !contentDomainPattern.MatchString(d) {
		return "", fmt.Errorf("content domain %q must be a bare hostname", raw)
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("base URL: %w", err)
	}
	if h := strings.ToLower(base.Hostname()); h == d || strings.HasSuffix(h, "."+d) {
		return "", fmt.Errorf("content domain %q covers base URL host %q", d, h)
	}
	return d, nil
}

// contentLabel reports whether host is the content domain or under it, and
// returns what precedes the domain. Case and trailing dots do not change the
// answer, so no spelling of a content host falls through to the admin router. A
// trailing dot leaves label unusable, so such a host is routed here and gets 404.
func contentLabel(host, contentDomain string) (label string, ok bool) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	bare := strings.TrimRight(host, ".")
	if bare != contentDomain && !strings.HasSuffix(bare, "."+contentDomain) {
		return "", false
	}
	return strings.TrimSuffix(host, "."+contentDomain), true
}

// contentHandler is a separate router, so admin and API handlers cannot be
// reached from a content host.
func (s *Server) contentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /"+sites.ReservedDir+"/login", s.grantLoginGET)
	mux.HandleFunc("POST /"+sites.ReservedDir+"/login", s.grantLoginPOST)
	mux.HandleFunc("GET /"+sites.ReservedDir+"/link/{token}", s.linkGET)
	mux.HandleFunc("POST /"+sites.ReservedDir+"/link/{token}", s.linkPOST)
	mux.HandleFunc("/"+sites.ReservedDir+"/", http.NotFound)
	mux.HandleFunc("/", s.serveContent)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "private, no-store")
		h.Set("X-Robots-Tag", "noindex")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", serverPageCSP)
		// A worker could keep serving a page after its grants end, and could
		// intercept the server's own routes on this origin.
		if r.Header.Get("Service-Worker") != "" {
			http.NotFound(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// contentURL is the site's root on its content host. It takes scheme and port
// from the base URL, since both hosts sit behind the same listener.
func (s *Server) contentURL(id domain.SiteID) string {
	scheme, host := "https", string(id)+"."+s.ContentDomain
	if base, err := url.Parse(s.BaseURL); err == nil {
		if base.Scheme != "" {
			scheme = base.Scheme
		}
		if port := base.Port(); port != "" {
			host = net.JoinHostPort(host, port)
		}
	}
	return scheme + "://" + host + "/"
}

func (s *Server) contentSite(r *http.Request) (domain.Site, error) {
	label, ok := contentLabel(r.Host, s.ContentDomain)
	if !ok || !contentIDPattern.MatchString(label) {
		return domain.Site{}, domain.ErrNotFound
	}
	site, err := s.Host.Meta.Site(r.Context(), domain.SiteID(label))
	if err != nil {
		return domain.Site{}, err
	}
	active, err := s.Host.Meta.HasActiveGrant(r.Context(), site.ID, time.Now())
	if err != nil {
		return domain.Site{}, err
	}
	if !active {
		return domain.Site{}, domain.ErrNotFound
	}
	return site, nil
}

func (s *Server) serveContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	site, err := s.contentSite(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	allowed, err := s.contentAllowed(r, site)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !allowed {
		// Same redirect for every grant type, so it does not reveal which exist.
		http.Redirect(w, r, "/"+sites.ReservedDir+"/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	body, ctype, err := s.Host.OpenCurrent(r.Context(), site, r.URL.Path)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer body.Close()
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	w.Header().Set("Content-Security-Policy", contentCSP)
	_, _ = io.Copy(w, body)
}

// contentAllowed checks the database on every request, so revocation, expiry,
// password change, and site delete apply to the next request.
func (s *Server) contentAllowed(r *http.Request, site domain.Site) (bool, error) {
	actor, err := s.optionalPrincipal(r)
	if err != nil && !errors.Is(err, domain.ErrUnauthorized) {
		return false, err
	}
	if err == nil && actor != nil && domain.CanRead(actor, site) {
		return true, nil
	}
	c, err := r.Cookie(hostCookieName(r, cookieGrant))
	if err != nil || c.Value == "" {
		return false, nil
	}
	_, err = s.Host.Meta.GrantSession(r.Context(), site.ID, TokenHash(c.Value), time.Now())
	if errors.Is(err, domain.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}
