package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/sites"
)

const (
	goodPassword = "correct horse battery"
	testCSRF     = "csrf-token"
)

func (f *contentFixture) api(method, path, bearer, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "artifacts.test"
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

func passwordBody(t *testing.T, password string) string {
	t.Helper()
	b, err := json.Marshal(map[string]string{"password": password})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (f *contentFixture) setPassword(site domain.SiteID, password string) {
	f.t.Helper()
	wantStatus(f.t, f.api(http.MethodPut, "/v1/sites/"+string(site)+"/password", f.token, passwordBody(f.t, password)), http.StatusNoContent)
}

type loginReq struct {
	site     domain.SiteID
	password string
	next     string
	ip       string
	csrf     string
	origin   string
	https    bool
}

func (f *contentFixture) login(q loginReq) *httptest.ResponseRecorder {
	f.t.Helper()
	if q.csrf == "" {
		q.csrf = testCSRF
	}
	form := url.Values{"csrf": {q.csrf}, "password": {q.password}, "next": {q.next}}
	r := httptest.NewRequest(http.MethodPost, "/__ah/login", strings.NewReader(form.Encode()))
	r.Host = hostOf(q.site)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: cookieCSRF, Value: testCSRF})
	if q.https {
		r.Header.Set("X-Forwarded-Proto", "https")
		r.AddCookie(&http.Cookie{Name: "__Host-" + cookieCSRF, Value: testCSRF})
	}
	if q.ip != "" {
		r.Header.Set("X-Forwarded-For", q.ip)
	}
	if q.origin != "" {
		r.Header.Set("Origin", q.origin)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

func responseCookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s cookie in %v", name, w.Header()["Set-Cookie"])
	return nil
}

// loginSession logs in and returns the grant cookie value.
func (f *contentFixture) loginSession(site domain.SiteID, password string) string {
	f.t.Helper()
	w := f.login(loginReq{site: site, password: password})
	wantStatus(f.t, w, http.StatusSeeOther)
	return responseCookie(f.t, w, cookieGrant).Value
}

func (f *contentFixture) viewerSees(site domain.SiteID, cookie string) bool {
	f.t.Helper()
	w := f.do(contentReq{host: hostOf(site), path: "/", cookie: cookie})
	return w.Code == http.StatusOK && w.Body.String() == "site home"
}

// V4
func TestPasswordAPIOnlyOwnerManages(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	if err := f.db.CreateUser(ctx, "member", "member", TokenHash("member-token")); err != nil {
		t.Fatal(err)
	}
	if err := f.db.CreateTeam(ctx, "team", "team"); err != nil {
		t.Fatal(err)
	}
	if err := f.db.AddMember(ctx, "team", "member"); err != nil {
		t.Fatal(err)
	}
	if err := f.db.AddMember(ctx, "team", "owner"); err != nil {
		t.Fatal(err)
	}
	out, err := f.srv.Host.Publish(ctx, f.owner, sites.PublishIn{Visibility: domain.VisTeam, Team: "team", Files: []domain.File{{Path: "index.html", Body: []byte("x")}}})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/sites/" + string(out.Site) + "/password"
	body := passwordBody(t, goodPassword)
	for _, tc := range []struct {
		name   string
		bearer string
		code   int
	}{
		{"anonymous", "", http.StatusUnauthorized},
		{"team member", "member-token", http.StatusForbidden},
		{"other user", "other-token", http.StatusForbidden},
		{"admin", "admintok", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantStatus(t, f.api(http.MethodPut, path, tc.bearer, body), tc.code)
			wantStatus(t, f.api(http.MethodDelete, path, tc.bearer, ""), tc.code)
			if _, err := f.db.SitePassword(ctx, out.Site); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("password after refused PUT: %v", err)
			}
		})
	}
	wantStatus(t, f.api(http.MethodPut, "/v1/sites/missing/password", f.token, body), http.StatusNotFound)
	wantStatus(t, f.api(http.MethodPut, path, f.token, body), http.StatusNoContent)
	wantStatus(t, f.api(http.MethodDelete, path, "admintok", ""), http.StatusForbidden)
	if _, err := f.db.SitePassword(ctx, out.Site); err != nil {
		t.Fatalf("admin DELETE changed password: %v", err)
	}
	wantStatus(t, f.api(http.MethodDelete, path, f.token, ""), http.StatusNoContent)
	wantStatus(t, f.api(http.MethodDelete, path, f.token, ""), http.StatusNoContent)
	if _, err := f.db.SitePassword(ctx, out.Site); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("password after DELETE: %v", err)
	}
}

// V8
func TestPasswordAPIValidatesBody(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	path := "/v1/sites/" + string(site) + "/password"
	for _, tc := range []struct {
		name string
		body string
		code int
	}{
		{"7 bytes", passwordBody(t, strings.Repeat("a", 7)), http.StatusBadRequest},
		{"8 bytes", passwordBody(t, strings.Repeat("a", 8)), http.StatusNoContent},
		{"1024 bytes", passwordBody(t, strings.Repeat("a", 1024)), http.StatusNoContent},
		{"1025 bytes", passwordBody(t, strings.Repeat("a", 1025)), http.StatusBadRequest},
		{"bytes not characters", passwordBody(t, strings.Repeat("é", 4)), http.StatusNoContent},
		{"missing field", `{}`, http.StatusBadRequest},
		{"null", `{"password":null}`, http.StatusBadRequest},
		{"not JSON", `hunter2hunter2`, http.StatusBadRequest},
		{"trailing data", passwordBody(t, goodPassword) + `{}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := f.api(http.MethodPut, path, f.token, tc.body)
			wantStatus(t, w, tc.code)
			if strings.Contains(w.Body.String(), "hunter2") {
				t.Fatalf("response echoes body: %q", w.Body.String())
			}
		})
	}
}

// V8
func TestPasswordStoredOnlyAsArgon2id(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	w := f.api(http.MethodPut, "/v1/sites/"+string(site)+"/password", f.token, passwordBody(t, goodPassword))
	wantStatus(t, w, http.StatusNoContent)
	if w.Body.Len() != 0 {
		t.Fatalf("PUT response has a body: %q", w.Body.String())
	}
	p, err := f.db.SitePassword(context.Background(), site)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.Hash, "$argon2id$v=19$m=65536,t=3,p=4$") || strings.Contains(p.Hash, goodPassword) {
		t.Fatalf("hash %q", p.Hash)
	}
}

// V14
func TestPasswordRefusedOnPublicSite(t *testing.T) {
	f := newContentFixture(t)
	out, err := f.srv.Host.Publish(context.Background(), f.owner, sites.PublishIn{Visibility: domain.VisPublic, Files: []domain.File{{Path: "index.html", Body: []byte("x")}}})
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, f.api(http.MethodPut, "/v1/sites/"+string(out.Site)+"/password", f.token, passwordBody(t, goodPassword)), http.StatusBadRequest)
	if _, err := f.db.SitePassword(context.Background(), out.Site); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("password stored: %v", err)
	}
}

// V1, V7
func TestLoginGrantsSiteThroughTheForm(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)

	anon := f.do(contentReq{host: hostOf(site), path: "/admin/index.html?x=1"})
	wantStatus(t, anon, http.StatusSeeOther)
	form := f.do(contentReq{host: hostOf(site), path: anon.Header().Get("Location")})
	wantStatus(t, form, http.StatusOK)
	if got := form.Header().Get("Content-Security-Policy"); got != serverPageCSP {
		t.Fatalf("CSP %q", got)
	}
	csrf := responseCookie(t, form, cookieCSRF).Value
	body := form.Body.String()
	if !strings.Contains(body, `name="csrf" value="`+csrf+`"`) || !strings.Contains(body, "/admin/index.html?x=1") {
		t.Fatalf("form missing csrf or next: %s", body)
	}

	w := f.login(loginReq{site: site, password: goodPassword, next: "/admin/index.html?x=1"})
	wantStatus(t, w, http.StatusSeeOther)
	if got := w.Header().Get("Location"); got != "/admin/index.html?x=1" {
		t.Fatalf("Location %q", got)
	}
	cookie := responseCookie(t, w, cookieGrant)
	page := f.do(contentReq{host: hostOf(site), path: "/admin/index.html", cookie: cookie.Value})
	wantStatus(t, page, http.StatusOK)
	if page.Body.String() != "site admin file" {
		t.Fatalf("body %q", page.Body.String())
	}
}

// V7
func TestLoginCookieShape(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	w := f.login(loginReq{site: site, password: goodPassword, https: true})
	wantStatus(t, w, http.StatusSeeOther)
	c := responseCookie(t, w, "__Host-"+cookieGrant)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie %+v", c)
	}
	if c.MaxAge != int((24 * time.Hour).Seconds()) {
		t.Fatalf("MaxAge %d", c.MaxAge)
	}
	if strings.Contains(c.Value, goodPassword) || len(c.Value) != 64 {
		t.Fatalf("cookie value %q", c.Value)
	}
	ctx := context.Background()
	if _, err := f.db.GrantSession(ctx, site, TokenHash(c.Value), time.Now()); err != nil {
		t.Fatalf("session stored under hash: %v", err)
	}
	if _, err := f.db.GrantSession(ctx, site, []byte(c.Value), time.Now()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("session stored under raw id: %v", err)
	}
	s, err := f.db.GrantSession(ctx, site, TokenHash(c.Value), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(s.ExpiresAt); left > 24*time.Hour || left < 23*time.Hour {
		t.Fatalf("session lasts %s", left)
	}
}

// V1
func TestLoginDoesNotWidenToAnotherSite(t *testing.T) {
	f := newContentFixture(t)
	a, b := f.site(), f.site()
	f.setPassword(a, goodPassword)
	f.setPassword(b, "another password")
	cookie := f.loginSession(a, goodPassword)
	if !f.viewerSees(a, cookie) {
		t.Fatal("session does not grant its own site")
	}
	if f.viewerSees(b, cookie) {
		t.Fatal("session grants another site")
	}
	wantStatus(t, f.login(loginReq{site: b, password: goodPassword}), http.StatusUnauthorized)
}

// V2
func TestPasswordChangeEndsOnlyPasswordSessions(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	password := f.loginSession(site, goodPassword)
	link := f.session(domain.GrantSession{Site: site, Link: f.link(site)})

	f.setPassword(site, "a newer password")
	if f.viewerSees(site, password) {
		t.Fatal("old password session still works")
	}
	if !f.viewerSees(site, link) {
		t.Fatal("password change ended link session")
	}
	wantStatus(t, f.login(loginReq{site: site, password: goodPassword}), http.StatusUnauthorized)
	current := f.loginSession(site, "a newer password")

	wantStatus(t, f.api(http.MethodDelete, "/v1/sites/"+string(site)+"/password", f.token, ""), http.StatusNoContent)
	if f.viewerSees(site, current) {
		t.Fatal("cleared password session still works")
	}
	if !f.viewerSees(site, link) {
		t.Fatal("clearing password ended link session")
	}
}

// V3
func TestLoginSessionSurvivesRestart(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	cookie := f.loginSession(site, goodPassword)

	restarted := New(f.srv.Host, "admintok", "https://artifacts.test")
	restarted.ContentDomain = contentZone
	f.handler = restarted.Handler()
	if !f.viewerSees(site, cookie) {
		t.Fatal("session lost across restart")
	}
}

// V5
func TestLoginRoutesRespectContentRouter(t *testing.T) {
	f := newContentFixture(t)
	noGrant := f.site()
	wantStatus(t, f.do(contentReq{host: hostOf(noGrant), path: "/__ah/login"}), http.StatusNotFound)
	wantStatus(t, f.login(loginReq{site: noGrant, password: goodPassword}), http.StatusNotFound)
	wantStatus(t, f.do(contentReq{host: strings.Repeat("0", 32) + "." + contentZone, path: "/__ah/login"}), http.StatusNotFound)

	site := f.site()
	f.setPassword(site, goodPassword)
	wantStatus(t, f.do(contentReq{method: http.MethodPut, host: hostOf(site), path: "/__ah/login"}), http.StatusNotFound)
	wantStatus(t, f.do(contentReq{host: "artifacts.test", path: "/__ah/login"}), http.StatusNotFound)
	if got := f.do(contentReq{host: hostOf(site), path: "/__ah/login"}); got.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("Cache-Control %q", got.Header().Get("Cache-Control"))
	}
}

// V9
func TestLoginRequiresCSRF(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	wantStatus(t, f.login(loginReq{site: site, password: goodPassword, csrf: "wrong"}), http.StatusForbidden)
	wantStatus(t, f.login(loginReq{site: site, password: goodPassword, origin: "https://evil.test"}), http.StatusForbidden)

	big := httptest.NewRequest(http.MethodPost, "/__ah/login", strings.NewReader("csrf="+testCSRF+"&password="+strings.Repeat("a", grantLoginBodyMax)))
	big.Host = hostOf(site)
	big.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	big.AddCookie(&http.Cookie{Name: cookieCSRF, Value: testCSRF})
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, big)
	wantStatus(t, w, http.StatusForbidden)

	// A CSRF failure must not use up the limit.
	for range loginMaxFail + 1 {
		wantStatus(t, f.login(loginReq{site: site, password: "x", csrf: "wrong", ip: "198.51.100.1"}), http.StatusForbidden)
	}
	wantStatus(t, f.login(loginReq{site: site, password: goodPassword, ip: "198.51.100.1"}), http.StatusSeeOther)
}

// V9
func TestLoginLimitedPerSiteAndIP(t *testing.T) {
	f := newContentFixture(t)
	site, other := f.site(), f.site()
	f.setPassword(site, goodPassword)
	f.setPassword(other, goodPassword)
	const ip = "198.51.100.2"
	for range loginMaxFail {
		wantStatus(t, f.login(loginReq{site: site, password: "wrong password", ip: ip}), http.StatusUnauthorized)
	}
	limited := f.login(loginReq{site: site, password: goodPassword, ip: ip})
	wantStatus(t, limited, http.StatusTooManyRequests)
	if got := limited.Header().Get("Retry-After"); got != "900" {
		t.Fatalf("Retry-After %q", got)
	}
	if _, ok := limited.Result().Header["Set-Cookie"]; ok {
		t.Fatal("limited response set a cookie")
	}
	wantStatus(t, f.login(loginReq{site: site, password: goodPassword, ip: "198.51.100.3"}), http.StatusSeeOther)
	wantStatus(t, f.login(loginReq{site: other, password: goodPassword, ip: ip}), http.StatusSeeOther)
}

// V9
func TestLoginSuccessResetsOnlyItsOwnIP(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	const ip = "198.51.100.4"
	for range loginMaxFail - 1 {
		wantStatus(t, f.login(loginReq{site: site, password: "wrong password", ip: ip}), http.StatusUnauthorized)
	}
	wantStatus(t, f.login(loginReq{site: site, password: goodPassword, ip: ip}), http.StatusSeeOther)
	if n := len(f.srv.grantLogins.fail[string(site)+"|"+ip]); n != 0 {
		t.Fatalf("site+IP attempts after success: %d", n)
	}
	if n := len(f.srv.grantLogins.fail[string(site)]); n != loginMaxFail-1 {
		t.Fatalf("site attempts after success: %d, want failures kept and success refunded", n)
	}
}

// V9
func TestLoginLimitedPerSiteOverall(t *testing.T) {
	f := newContentFixture(t)
	site, other := f.site(), f.site()
	f.setPassword(site, goodPassword)
	f.setPassword(other, goodPassword)
	for range grantFailsPerSite {
		if !f.srv.grantLogins.reserve(limitKey{string(site), grantFailsPerSite}) {
			t.Fatal("reserve refused below limit")
		}
	}
	wantStatus(t, f.login(loginReq{site: site, password: goodPassword, ip: "198.51.100.5"}), http.StatusTooManyRequests)
	if n := len(f.srv.grantLogins.fail[string(site)+"|198.51.100.5"]); n != 0 {
		t.Fatalf("refused attempt counted against IP: %d", n)
	}
	wantStatus(t, f.login(loginReq{site: other, password: goodPassword, ip: "198.51.100.5"}), http.StatusSeeOther)
}

// V9
func TestLoginDoesNotRevealOtherGrants(t *testing.T) {
	f := newContentFixture(t)
	withPassword, linkOnly := f.site(), f.site()
	f.setPassword(withPassword, goodPassword)
	f.link(linkOnly)

	a := f.login(loginReq{site: withPassword, password: "wrong password", ip: "198.51.100.6"})
	b := f.login(loginReq{site: linkOnly, password: "wrong password", ip: "198.51.100.6"})
	wantStatus(t, a, http.StatusUnauthorized)
	wantStatus(t, b, http.StatusUnauthorized)
	if a.Body.String() != b.Body.String() {
		t.Fatalf("responses differ:\n%s\n%s", a.Body.String(), b.Body.String())
	}
	if strings.Contains(a.Body.String(), "wrong password") {
		t.Fatal("form echoes submitted password")
	}
	wantStatus(t, f.do(contentReq{host: hostOf(linkOnly), path: "/__ah/login"}), http.StatusOK)

	for range loginMaxFail - 1 {
		f.login(loginReq{site: withPassword, password: "wrong password", ip: "198.51.100.6"})
		f.login(loginReq{site: linkOnly, password: "wrong password", ip: "198.51.100.6"})
	}
	a = f.login(loginReq{site: withPassword, password: "wrong password", ip: "198.51.100.6"})
	b = f.login(loginReq{site: linkOnly, password: "wrong password", ip: "198.51.100.6"})
	wantStatus(t, a, http.StatusTooManyRequests)
	wantStatus(t, b, http.StatusTooManyRequests)
	if a.Body.String() != b.Body.String() {
		t.Fatalf("limit responses differ:\n%s\n%s", a.Body.String(), b.Body.String())
	}
}

// V12
func TestLoginRedirectStaysOnHost(t *testing.T) {
	for _, tc := range []struct{ next, want string }{
		{"/", "/"},
		{"/a/b.html?x=1#f", "/a/b.html?x=1#f"},
		{"", "/"},
		{"a/b", "/"},
		{"//evil.test/", "/"},
		{"///evil.test/", "/"},
		{"https://evil.test/", "/"},
		{"javascript:alert(1)", "/"},
		{`/\evil.test/`, "/"},
		{`\\evil.test/`, "/"},
		{"/\t/evil.test/", "/"},
		{"/\n/evil.test/", "/"},
		{"/\r\nSet-Cookie: a=b", "/"},
		{"/%zz", "/"},
	} {
		if got := safeNext(tc.next); got != tc.want {
			t.Errorf("safeNext(%q) = %q, want %q", tc.next, got, tc.want)
		}
	}

	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	w := f.login(loginReq{site: site, password: goodPassword, next: "//evil.test/"})
	wantStatus(t, w, http.StatusSeeOther)
	if got := w.Header().Get("Location"); got != "/" {
		t.Fatalf("Location %q", got)
	}
	form := f.do(contentReq{host: hostOf(site), path: "/__ah/login?next=" + url.QueryEscape("//evil.test/")})
	if strings.Contains(form.Body.String(), "evil.test") {
		t.Fatalf("form keeps unsafe next: %s", form.Body.String())
	}
}

func TestLoginLimitSweepsStaleKeys(t *testing.T) {
	l := newLoginLimit()
	if !l.begin("gone") {
		t.Fatal("begin refused")
	}
	l.fail["gone"][0] = time.Now().Add(-2 * loginWindow)
	l.lastSweep = time.Now().Add(-2 * loginWindow)
	if !l.begin("new") {
		t.Fatal("begin refused")
	}
	if _, ok := l.fail["gone"]; ok {
		t.Fatal("stale key kept")
	}
}

func TestLoginLimitReservesAllKeysOrNone(t *testing.T) {
	l := newLoginLimit()
	if !l.reserve(limitKey{"full", 1}) {
		t.Fatal("reserve refused")
	}
	if l.reserve(limitKey{"other", 5}, limitKey{"full", 1}) {
		t.Fatal("reserve passed a full key")
	}
	if n := len(l.fail["other"]); n != 0 {
		t.Fatalf("refused reserve counted %d attempts", n)
	}
}
