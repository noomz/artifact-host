package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noomz/artifact-host/internal/blob"
	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/meta"
	"github.com/noomz/artifact-host/internal/sites"
)

const (
	contentZone = "u.test"
	testArgon   = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
)

type contentFixture struct {
	t       *testing.T
	srv     *Server
	handler http.Handler
	db      *meta.DB
	owner   domain.Principal
	token   string
}

func newContentFixture(t *testing.T) *contentFixture {
	t.Helper()
	db, err := meta.Open(filepath.Join(t.TempDir(), "content.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	for _, u := range []struct {
		id    domain.UserID
		token string
	}{{"owner", "owner-token"}, {"other", "other-token"}} {
		if err := db.CreateUser(ctx, u.id, string(u.id), TokenHash(u.token)); err != nil {
			t.Fatal(err)
		}
	}
	srv := New(sites.New(db, blob.NewMemory()), "admintok", "https://artifacts.test")
	srv.ContentDomain = contentZone
	return &contentFixture{t: t, srv: srv, handler: srv.Handler(), db: db, owner: domain.Principal{User: "owner"}, token: "owner-token"}
}

func (f *contentFixture) site() domain.SiteID {
	f.t.Helper()
	return f.publish("", domain.VisOwner)
}

// publish creates a site, or republishes one when id is set.
func (f *contentFixture) publish(id domain.SiteID, vis domain.Visibility) domain.SiteID {
	f.t.Helper()
	out, err := f.srv.Host.Publish(context.Background(), f.owner, sites.PublishIn{
		Site:       id,
		Visibility: vis,
		Files: []domain.File{
			{Path: "index.html", Body: []byte("site home")},
			{Path: "admin/index.html", Body: []byte("site admin file")},
			{Path: "v1/a.html", Body: []byte("site v1 file")},
		},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out.Site
}

func (f *contentFixture) password(site domain.SiteID) domain.PasswordID {
	f.t.Helper()
	id := domain.PasswordID(sites.NewID())
	if err := f.db.SetSitePassword(context.Background(), domain.SitePassword{ID: id, Site: site, Hash: testArgon}); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *contentFixture) link(site domain.SiteID) domain.LinkID {
	f.t.Helper()
	id := domain.LinkID(sites.NewID())
	now := time.Now()
	l := domain.SiteLink{ID: id, Site: site, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := f.db.CreateSiteLink(context.Background(), l, TokenHash(sites.NewID())); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *contentFixture) session(s domain.GrantSession) string {
	f.t.Helper()
	raw := sites.NewID()
	now := time.Now()
	if s.ExpiresAt.IsZero() {
		s.ExpiresAt = now.Add(time.Hour)
	}
	if s.ExpiresAt.Before(now) {
		now = s.ExpiresAt.Add(-time.Hour)
	}
	if err := f.db.CreateGrantSession(context.Background(), s, TokenHash(raw), now); err != nil {
		f.t.Fatal(err)
	}
	return raw
}

type contentReq struct {
	method  string
	host    string
	path    string
	cookie  string
	bearer  string
	headers map[string]string
}

func (f *contentFixture) do(q contentReq) *httptest.ResponseRecorder {
	f.t.Helper()
	if q.method == "" {
		q.method = http.MethodGet
	}
	r := httptest.NewRequest(q.method, q.path, nil)
	r.Host = q.host
	if q.cookie != "" {
		r.AddCookie(&http.Cookie{Name: cookieGrant, Value: q.cookie})
	}
	if q.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+q.bearer)
	}
	for k, v := range q.headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

func hostOf(site domain.SiteID) string { return string(site) + "." + contentZone }

func wantStatus(t *testing.T, w *httptest.ResponseRecorder, code int) {
	t.Helper()
	if w.Code != code {
		t.Fatalf("status %d, want %d, body %q", w.Code, code, w.Body.String())
	}
}

func wantLoginRedirect(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	wantStatus(t, w, http.StatusSeeOther)
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/__ah/login?next=") {
		t.Fatalf("Location %q", loc)
	}
}

// V5: every host that is not a valid site ID directly under the content domain
// gets 404, including paths the main router would serve.
func TestContentHostRejectsBadHosts(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.password(site)
	id := string(site)
	hosts := map[string]string{
		"apex":               contentZone,
		"non-hex label":      "bad." + contentZone,
		"short ID":           id[:31] + "." + contentZone,
		"long ID":            id + "0." + contentZone,
		"nested label":       "a." + id + "." + contentZone,
		"trailing dot":       id + "." + contentZone + ".",
		"two trailing dots":  id + "." + contentZone + "..",
		"upper apex":         strings.ToUpper(contentZone),
		"unknown site":       strings.Repeat("0", 32) + "." + contentZone,
		"unknown with port":  strings.Repeat("0", 32) + "." + contentZone + ":8080",
		"non-hex ID, 32 len": strings.Repeat("g", 32) + "." + contentZone,
	}
	for name, host := range hosts {
		for _, path := range []string{"/", "/admin", "/admin/login", "/healthz", "/v1/sites", "/s/" + id + "/"} {
			t.Run(name+" "+path, func(t *testing.T) {
				wantStatus(t, f.do(contentReq{host: host, path: path, bearer: "admintok"}), http.StatusNotFound)
			})
		}
	}
}

// V5: no spelling of a content host reaches the main router.
func TestContentHostCaseAndPortStayOnContentRouter(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.password(site)
	for _, host := range []string{hostOf(site), strings.ToUpper(hostOf(site)), hostOf(site) + ":8080"} {
		t.Run(host, func(t *testing.T) {
			wantLoginRedirect(t, f.do(contentReq{host: host, path: "/admin/login"}))
		})
	}
}

// V5: admin and API handlers cannot be reached, even with the admin token.
func TestContentHostNeverReachesAdminOrAPI(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.password(site)
	host := hostOf(site)
	for _, q := range []contentReq{
		{path: "/admin"},
		{path: "/admin/login"},
		{path: "/healthz"},
		{path: "/v1/sites"},
		{path: "/s/" + string(site) + "/"},
		{method: http.MethodPost, path: "/admin/login"},
		{method: http.MethodPost, path: "/admin/users"},
		{method: http.MethodPost, path: "/v1/users"},
		{method: http.MethodPost, path: "/v1/sites"},
		{method: http.MethodPatch, path: "/v1/sites/" + string(site)},
		{method: http.MethodDelete, path: "/"},
	} {
		q.host, q.bearer = host, "admintok"
		// The admin token can read the site, so only a site file could answer,
		// and this site has none at these paths.
		w := f.do(q)
		wantStatus(t, w, http.StatusNotFound)
		if body := w.Body.String(); strings.Contains(body, "<form") || strings.Contains(body, `"id"`) || body == "ok" {
			t.Fatalf("%s %s served %q", q.method, q.path, body)
		}
	}
}

// V5: those paths are ordinary site paths, so published files there are served.
func TestContentHostServesSiteFilesAtRouterPaths(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	p := f.password(site)
	cookie := f.session(domain.GrantSession{Site: site, Password: p})
	for path, want := range map[string]string{
		"/":                 "site home",
		"/index.html":       "site home",
		"/admin/index.html": "site admin file",
		"/v1/a.html":        "site v1 file",
	} {
		w := f.do(contentReq{host: hostOf(site), path: path, cookie: cookie})
		wantStatus(t, w, http.StatusOK)
		if w.Body.String() != want {
			t.Fatalf("%s body %q, want %q", path, w.Body.String(), want)
		}
	}
	wantStatus(t, f.do(contentReq{host: hostOf(site), path: "/missing.html", cookie: cookie}), http.StatusNotFound)
	wantStatus(t, f.do(contentReq{host: hostOf(site), path: "/", cookie: cookie, method: http.MethodPost}), http.StatusNotFound)
}

func TestMainHostUnaffectedByContentDomain(t *testing.T) {
	f := newContentFixture(t)
	for _, host := range []string{"artifacts.test", "evilu.test"} {
		wantStatus(t, f.do(contentReq{host: host, path: "/healthz"}), http.StatusOK)
		wantStatus(t, f.do(contentReq{host: host, path: "/__ah/login"}), http.StatusNotFound)
	}
}

func TestContentDomainEmptyDisablesContentHosts(t *testing.T) {
	f := newContentFixture(t)
	f.srv.ContentDomain = ""
	f.handler = f.srv.Handler()
	site := f.site()
	f.password(site)
	wantStatus(t, f.do(contentReq{host: hostOf(site), path: "/healthz"}), http.StatusOK)
}

// V5: a private site without an active grant is absent from the content host,
// for its owner too.
func TestContentHostSiteWithoutGrantIs404(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	wantStatus(t, f.do(contentReq{host: hostOf(site), path: "/", bearer: f.token}), http.StatusNotFound)
	wantStatus(t, f.do(contentReq{host: hostOf(site), path: "/"}), http.StatusNotFound)
}

// The response must not reveal which grant the site has.
func TestContentAnonymousRedirectSameForEachGrant(t *testing.T) {
	f := newContentFixture(t)
	withPassword, withLink := f.site(), f.site()
	f.password(withPassword)
	f.link(withLink)
	a := f.do(contentReq{host: hostOf(withPassword), path: "/a?b=c"})
	b := f.do(contentReq{host: hostOf(withLink), path: "/a?b=c"})
	wantLoginRedirect(t, a)
	wantLoginRedirect(t, b)
	if a.Header().Get("Location") != "/__ah/login?next=%2Fa%3Fb%3Dc" || a.Header().Get("Location") != b.Header().Get("Location") {
		t.Fatalf("Location %q and %q", a.Header().Get("Location"), b.Header().Get("Location"))
	}
}

// V1: each credential grants read on its own, and never another site.
func TestContentGrantsStayOnOneSite(t *testing.T) {
	f := newContentFixture(t)
	a, b := f.site(), f.site()
	pa := f.password(a)
	f.password(b)
	la := f.link(a)
	for name, s := range map[string]domain.GrantSession{
		"password session": {Site: a, Password: pa},
		"link session":     {Site: a, Link: la},
	} {
		t.Run(name, func(t *testing.T) {
			cookie := f.session(s)
			wantStatus(t, f.do(contentReq{host: hostOf(a), path: "/", cookie: cookie}), http.StatusOK)
			wantLoginRedirect(t, f.do(contentReq{host: hostOf(b), path: "/", cookie: cookie}))
		})
	}
}

func TestContentBearer(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.password(site)
	wantStatus(t, f.do(contentReq{host: hostOf(site), path: "/", bearer: f.token}), http.StatusOK)
	wantLoginRedirect(t, f.do(contentReq{host: hostOf(site), path: "/", bearer: "other-token"}))
	wantLoginRedirect(t, f.do(contentReq{host: hostOf(site), path: "/", bearer: "invalid-token"}))
}

// V2, V3: ending one grant ends its sessions on the next request and leaves the
// other grant working.
func TestContentRevocationAppliesOnNextRequest(t *testing.T) {
	ctx := context.Background()
	f := newContentFixture(t)
	site := f.site()
	p, l := f.password(site), f.link(site)
	byPassword := f.session(domain.GrantSession{Site: site, Password: p})
	byLink := f.session(domain.GrantSession{Site: site, Link: l})
	get := func(cookie string) *httptest.ResponseRecorder {
		return f.do(contentReq{host: hostOf(site), path: "/", cookie: cookie})
	}
	wantStatus(t, get(byPassword), http.StatusOK)
	wantStatus(t, get(byLink), http.StatusOK)

	if err := f.db.ClearSitePassword(ctx, site); err != nil {
		t.Fatal(err)
	}
	wantLoginRedirect(t, get(byPassword))
	wantStatus(t, get(byLink), http.StatusOK)

	second := f.password(site)
	byPassword = f.session(domain.GrantSession{Site: site, Password: second})
	if err := f.db.RevokeSiteLink(ctx, site, l); err != nil {
		t.Fatal(err)
	}
	wantLoginRedirect(t, get(byLink))
	wantStatus(t, get(byPassword), http.StatusOK)

	if err := f.srv.Host.DeleteSite(ctx, site); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, get(byPassword), http.StatusNotFound)
}

func TestContentExpiredSessionDenied(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	p := f.password(site)
	cookie := f.session(domain.GrantSession{Site: site, Password: p, ExpiresAt: time.Now().Add(-time.Minute)})
	wantLoginRedirect(t, f.do(contentReq{host: hostOf(site), path: "/", cookie: cookie}))
}

// V7: on HTTPS only the __Host- name counts, so a cookie planted by a sibling
// host under the plain name is ignored.
func TestContentHTTPSReadsOnlyPrefixedCookie(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	p := f.password(site)
	raw := f.session(domain.GrantSession{Site: site, Password: p})
	https := map[string]string{"X-Forwarded-Proto": "https"}
	wantLoginRedirect(t, f.do(contentReq{host: hostOf(site), path: "/", cookie: raw, headers: https}))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = hostOf(site)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.AddCookie(&http.Cookie{Name: "__Host-" + cookieGrant, Value: raw})
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	wantStatus(t, w, http.StatusOK)
}

// V12: privacy headers on every response, the lockdown CSP on site files.
func TestContentHeaders(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	p := f.password(site)
	cookie := f.session(domain.GrantSession{Site: site, Password: p})
	responses := map[string]contentReq{
		"file":      {host: hostOf(site), path: "/", cookie: cookie},
		"redirect":  {host: hostOf(site), path: "/"},
		"not found": {host: hostOf(site), path: "/missing", cookie: cookie},
		"bad host":  {host: "bad." + contentZone, path: "/"},
		"reserved":  {host: hostOf(site), path: "/__ah/nothing"},
	}
	for name, q := range responses {
		t.Run(name, func(t *testing.T) {
			h := f.do(q).Header()
			if got := h.Get("Cache-Control"); got != "private, no-store" {
				t.Errorf("Cache-Control %q", got)
			}
			if got := h.Get("X-Robots-Tag"); got != "noindex" {
				t.Errorf("X-Robots-Tag %q", got)
			}
			if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options %q", got)
			}
			want := serverPageCSP
			if name == "file" {
				want = contentCSP
			}
			if got := h.Get("Content-Security-Policy"); got != want {
				t.Errorf("CSP %q, want %q", got, want)
			}
		})
	}
	for _, directive := range []string{"form-action 'none'", "connect-src 'self'", "img-src 'self' data: blob:", "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'"} {
		if !strings.Contains(contentCSP, directive) {
			t.Errorf("contentCSP missing %q", directive)
		}
	}
	if strings.Contains(contentCSP, "sandbox") || strings.Contains(contentCSP, "*") {
		t.Errorf("contentCSP %q", contentCSP)
	}
}

// V20, V12: a public site is served to anyone, with the site CSP, indexable,
// and never cached.
func TestContentPublicSiteServedWithoutGrant(t *testing.T) {
	f := newContentFixture(t)
	site := f.publish("", domain.VisPublic)
	for name, q := range map[string]contentReq{
		"anonymous GET":  {host: hostOf(site), path: "/"},
		"anonymous HEAD": {method: http.MethodHead, host: hostOf(site), path: "/index.html"},
		"other user":     {host: hostOf(site), path: "/", bearer: "other-token"},
		"bad bearer":     {host: hostOf(site), path: "/", bearer: "invalid-token"},
	} {
		t.Run(name, func(t *testing.T) {
			w := f.do(q)
			wantStatus(t, w, http.StatusOK)
			if q.method == "" && w.Body.String() != "site home" {
				t.Errorf("body %q", w.Body.String())
			}
			h := w.Header()
			if got := h.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control %q", got)
			}
			if got, ok := h["X-Robots-Tag"]; ok {
				t.Errorf("X-Robots-Tag %q", got)
			}
			if got := h.Get("Content-Security-Policy"); got != contentCSP {
				t.Errorf("CSP %q", got)
			}
			if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options %q", got)
			}
		})
	}
}

// V5, V19: a public site's host serves its files and nothing else. Router paths
// are site files, and the grant routes do not exist.
func TestContentPublicSiteIsolation(t *testing.T) {
	f := newContentFixture(t)
	site := f.publish("", domain.VisPublic)
	host := hostOf(site)
	for path, body := range map[string]string{"/admin/index.html": "site admin file", "/v1/a.html": "site v1 file"} {
		w := f.do(contentReq{host: host, path: path})
		wantStatus(t, w, http.StatusOK)
		if w.Body.String() != body {
			t.Errorf("%s body %q", path, w.Body.String())
		}
	}
	for name, q := range map[string]contentReq{
		"POST file":      {method: http.MethodPost, host: host, path: "/"},
		"PUT file":       {method: http.MethodPut, host: host, path: "/index.html"},
		"login GET":      {host: host, path: "/__ah/login"},
		"login POST":     {method: http.MethodPost, host: host, path: "/__ah/login"},
		"link GET":       {host: host, path: "/__ah/link/" + strings.Repeat("a", 64)},
		"link POST":      {method: http.MethodPost, host: host, path: "/__ah/link/" + strings.Repeat("a", 64)},
		"reserved":       {host: host, path: "/__ah/nothing"},
		"missing file":   {host: host, path: "/missing"},
		"service worker": {host: host, path: "/index.html", headers: map[string]string{"Service-Worker": "script"}},
	} {
		t.Run(name, func(t *testing.T) {
			wantStatus(t, f.do(q), http.StatusNotFound)
		})
	}
}

// V20: visibility is read on every request.
func TestContentPublicVisibilityChangeAppliesNextRequest(t *testing.T) {
	f := newContentFixture(t)
	site := f.publish("", domain.VisPublic)
	get := func() *httptest.ResponseRecorder { return f.do(contentReq{host: hostOf(site), path: "/"}) }
	wantStatus(t, get(), http.StatusOK)
	f.publish(site, domain.VisOwner)
	wantStatus(t, get(), http.StatusNotFound)
	f.password(site)
	wantLoginRedirect(t, get())
	if err := f.db.ClearSitePassword(context.Background(), site); err != nil {
		t.Fatal(err)
	}
	f.publish(site, domain.VisPublic)
	wantStatus(t, get(), http.StatusOK)
}

// V19
func TestContentBlocksServiceWorkerScripts(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	p := f.password(site)
	cookie := f.session(domain.GrantSession{Site: site, Password: p})
	worker := map[string]string{"Service-Worker": "script"}
	wantStatus(t, f.do(contentReq{host: hostOf(site), path: "/index.html", cookie: cookie}), http.StatusOK)
	wantStatus(t, f.do(contentReq{host: hostOf(site), path: "/index.html", cookie: cookie, headers: worker}), http.StatusNotFound)
}

func TestContentRejectsPathEscape(t *testing.T) {
	f := newContentFixture(t)
	site, other := f.site(), f.site()
	p := f.password(site)
	cookie := f.session(domain.GrantSession{Site: site, Password: p})
	w := f.do(contentReq{host: hostOf(site), path: "/..%5c..%5c" + string(other) + "%5cindex.html", cookie: cookie})
	wantStatus(t, w, http.StatusBadRequest)
}

func TestParseContentDomain(t *testing.T) {
	const base = "https://artifacts.noomz.space"
	for raw, want := range map[string]string{
		"":                         "",
		"  ":                       "",
		"u.artifacts.noomz.space":  "u.artifacts.noomz.space",
		" U.Artifacts.Noomz.Space": "u.artifacts.noomz.space",
	} {
		got, err := ParseContentDomain(raw, base)
		if err != nil || got != want {
			t.Errorf("ParseContentDomain(%q) = %q, %v, want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"https://u.artifacts.noomz.space",
		"u.artifacts.noomz.space:443",
		"u.artifacts.noomz.space/",
		"*.u.artifacts.noomz.space",
		".u.artifacts.noomz.space",
		"localhost",
		"artifacts.noomz.space",
		"noomz.space",
	} {
		if got, err := ParseContentDomain(raw, base); err == nil {
			t.Errorf("ParseContentDomain(%q) = %q, want error", raw, got)
		}
	}
}
