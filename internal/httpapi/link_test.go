package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/sites"
)

type createdLink struct {
	ID        domain.LinkID `json:"id"`
	Label     string        `json:"label"`
	URL       string        `json:"url"`
	ExpiresAt time.Time     `json:"expires_at"`
	token     string
}

func (f *contentFixture) linkPath(site domain.SiteID) string {
	return "/v1/sites/" + string(site) + "/links"
}

func (f *contentFixture) createLink(site domain.SiteID, body string) createdLink {
	f.t.Helper()
	w := f.api(http.MethodPost, f.linkPath(site), f.token, body)
	wantStatus(f.t, w, http.StatusCreated)
	var l createdLink
	if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil {
		f.t.Fatal(err)
	}
	l.token = l.URL[strings.LastIndex(l.URL, "/")+1:]
	return l
}

type linkReq struct {
	site   domain.SiteID
	token  string
	csrf   string
	origin string
	https  bool
}

func (f *contentFixture) linkGet(site domain.SiteID, token string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(contentReq{host: hostOf(site), path: "/__ah/link/" + token})
}

func (f *contentFixture) linkPost(q linkReq) *httptest.ResponseRecorder {
	f.t.Helper()
	if q.csrf == "" {
		q.csrf = testCSRF
	}
	form := url.Values{"csrf": {q.csrf}}
	r := httptest.NewRequest(http.MethodPost, "/__ah/link/"+q.token, strings.NewReader(form.Encode()))
	r.Host = hostOf(q.site)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	name := cookieCSRF
	if q.https {
		r.Header.Set("X-Forwarded-Proto", "https")
		name = "__Host-" + cookieCSRF
	}
	r.AddCookie(&http.Cookie{Name: name, Value: testCSRF})
	if q.origin != "" {
		r.Header.Set("Origin", q.origin)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

// linkSession exchanges a link and returns the grant cookie value.
func (f *contentFixture) linkSession(site domain.SiteID, token string) string {
	f.t.Helper()
	w := f.linkPost(linkReq{site: site, token: token})
	wantStatus(f.t, w, http.StatusSeeOther)
	return responseCookie(f.t, w, cookieGrant).Value
}

// expiredLink stores a link that has already expired and returns its token.
func (f *contentFixture) expiredLink(site domain.SiteID) string {
	f.t.Helper()
	token := sites.NewID() + sites.NewID()
	now := time.Now()
	l := domain.SiteLink{ID: domain.LinkID(sites.NewID()), Site: site, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	if err := f.db.CreateSiteLink(context.Background(), l, TokenHash(token)); err != nil {
		f.t.Fatal(err)
	}
	return token
}

// V4
func TestLinkAPIOnlyOwnerManages(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	if err := f.db.CreateUser(ctx, "member", "member", TokenHash("member-token")); err != nil {
		t.Fatal(err)
	}
	if err := f.db.CreateTeam(ctx, "team", "team"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []domain.UserID{"member", "owner"} {
		if err := f.db.AddMember(ctx, "team", u); err != nil {
			t.Fatal(err)
		}
	}
	out, err := f.srv.Host.Publish(ctx, domain.Principal{User: "owner", Teams: []domain.TeamID{"team"}}, sites.PublishIn{
		Visibility: domain.VisTeam, Team: "team", Files: []domain.File{{Path: "index.html", Body: []byte("x")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	site := out.Site
	create := f.linkPath(site)
	for name, tc := range map[string]struct {
		bearer string
		code   int
	}{
		"team member": {"member-token", http.StatusForbidden},
		"other user":  {"other-token", http.StatusForbidden},
		"admin":       {"admintok", http.StatusForbidden},
		"anonymous":   {"", http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			wantStatus(t, f.api(http.MethodPost, create, tc.bearer, `{}`), tc.code)
			link := f.createLink(site, `{}`)
			wantStatus(t, f.api(http.MethodDelete, create+"/"+string(link.ID), tc.bearer, ""), tc.code)
			wantStatus(t, f.linkGet(site, link.token), http.StatusOK)
		})
	}

	link := f.createLink(site, `{"label":"  for Ada  "}`)
	if link.Label != "for Ada" {
		t.Fatalf("label %q", link.Label)
	}
	other := f.site()
	wantStatus(t, f.api(http.MethodDelete, f.linkPath(other)+"/"+string(link.ID), f.token, ""), http.StatusNotFound)
	wantStatus(t, f.api(http.MethodDelete, create+"/"+string(link.ID), f.token, ""), http.StatusNoContent)
	wantStatus(t, f.api(http.MethodDelete, create+"/"+string(link.ID), f.token, ""), http.StatusNotFound)
}

func TestLinkAPIValidatesBody(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	for name, body := range map[string]string{
		"empty":         "",
		"not json":      "nope",
		"two values":    `{} {}`,
		"number expiry": `{"expires_in":7}`,
		"long label":    `{"label":"` + strings.Repeat("a", 201) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			wantStatus(t, f.api(http.MethodPost, f.linkPath(site), f.token, body), http.StatusBadRequest)
		})
	}
	links, err := f.db.SiteLinks(context.Background(), site)
	if err != nil || len(links) != 0 {
		t.Fatalf("links stored: %+v %v", links, err)
	}
}

// I.host: empty content domain disables the feature. A token created here would
// have no URL, and could not be shown again.
func TestLinkRefusedWithoutContentDomain(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.srv.ContentDomain = ""
	f.handler = f.srv.Handler()
	wantStatus(t, f.api(http.MethodPost, f.linkPath(site), f.token, `{}`), http.StatusBadRequest)
	links, err := f.db.SiteLinks(context.Background(), site)
	if err != nil || len(links) != 0 {
		t.Fatalf("links stored: %+v %v", links, err)
	}
}

func TestLinkURLUsesBaseSchemeAndPort(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	if got, want := f.createLink(site, `{}`).URL, "https://"+hostOf(site)+"/__ah/link/"; !strings.HasPrefix(got, want) {
		t.Fatalf("url %q, want prefix %q", got, want)
	}
	f.srv.BaseURL = "http://localhost:8080"
	if got, want := f.createLink(site, `{}`).URL, "http://"+hostOf(site)+":8080/__ah/link/"; !strings.HasPrefix(got, want) {
		t.Fatalf("url %q, want prefix %q", got, want)
	}
}

// V14
func TestLinkRefusedOnPublicSite(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	files := []domain.File{{Path: "index.html", Body: []byte("x")}}
	public, err := f.srv.Host.Publish(ctx, f.owner, sites.PublishIn{Visibility: domain.VisPublic, Files: files})
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, f.api(http.MethodPost, f.linkPath(public.Site), f.token, `{}`), http.StatusBadRequest)

	site := f.site()
	f.createLink(site, `{}`)
	_, err = f.srv.Host.Publish(ctx, f.owner, sites.PublishIn{Site: site, Visibility: domain.VisPublic, Files: files})
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("publish public with link: %v", err)
	}
}

// V8
func TestLinkTokenStoredOnlyAsHashAndShownOnce(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	site := f.site()
	link := f.createLink(site, `{}`)
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(link.token) {
		t.Fatalf("token %q", link.token)
	}
	if _, err := f.db.SiteLinkByTokenHash(ctx, site, TokenHash(link.token), time.Now()); err != nil {
		t.Fatalf("not stored as SHA-256: %v", err)
	}
	if _, err := f.db.SiteLinkByTokenHash(ctx, site, []byte(link.token), time.Now()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("stored raw: %v", err)
	}
	exchange := f.linkPost(linkReq{site: site, token: link.token})
	wantStatus(t, exchange, http.StatusSeeOther)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"warning page": f.linkGet(site, link.token),
		"exchange":     exchange,
		"site list":    f.api(http.MethodGet, "/v1/sites", f.token, ""),
	} {
		if strings.Contains(w.Body.String(), link.token) {
			t.Fatalf("%s body holds token", name)
		}
		for k, v := range w.Header() {
			if strings.Contains(strings.Join(v, " "), link.token) {
				t.Fatalf("%s header %s holds token", name, k)
			}
		}
	}
}

// V10: nothing about the response tells these cases apart.
func TestDeadLinksGiveSame404(t *testing.T) {
	f := newContentFixture(t)
	site, other, noGrant := f.site(), f.site(), f.site()
	f.createLink(site, `{}`)
	revoked := f.createLink(site, `{}`)
	wantStatus(t, f.api(http.MethodDelete, f.linkPath(site)+"/"+string(revoked.ID), f.token, ""), http.StatusNoContent)
	foreign := f.createLink(other, `{}`)
	expiredOnly := f.site()

	cases := map[string]struct {
		site  domain.SiteID
		token string
	}{
		"invalid":      {site, strings.Repeat("0", 64)},
		"malformed":    {site, "x"},
		"expired":      {site, f.expiredLink(site)},
		"revoked":      {site, revoked.token},
		"other site":   {site, foreign.token},
		"no grants":    {noGrant, strings.Repeat("0", 64)},
		"only expired": {expiredOnly, f.expiredLink(expiredOnly)},
	}
	check := func(t *testing.T, w *httptest.ResponseRecorder) string {
		t.Helper()
		wantStatus(t, w, http.StatusNotFound)
		if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Fatalf("Referrer-Policy %q", got)
		}
		if len(w.Result().Cookies()) != 0 {
			t.Fatalf("cookies on 404: %v", w.Header()["Set-Cookie"])
		}
		return w.Body.String()
	}
	want := check(t, f.linkGet(site, strings.Repeat("0", 64)))
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := check(t, f.linkGet(tc.site, tc.token)); got != want {
				t.Fatalf("GET body %q, want %q", got, want)
			}
			if got := check(t, f.linkPost(linkReq{site: tc.site, token: tc.token})); got != want {
				t.Fatalf("POST body %q, want %q", got, want)
			}
			// A dead token must not reach the CSRF check, which answers differently.
			if got := check(t, f.linkPost(linkReq{site: tc.site, token: tc.token, csrf: "wrong"})); got != want {
				t.Fatalf("bad CSRF body %q, want %q", got, want)
			}
		})
	}
}

// V10
func TestLinkGetShowsWarningAndCreatesNoSession(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	link := f.createLink(site, `{}`)
	w := f.linkGet(site, link.token)
	wantStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), "Continue") {
		t.Fatalf("no Continue button: %q", w.Body.String())
	}
	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy %q", got)
	}
	if got := w.Header().Get("Content-Security-Policy"); got != serverPageCSP {
		t.Fatalf("CSP %q", got)
	}
	if got := w.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control %q", got)
	}
	var csrf string
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieGrant {
			t.Fatal("GET set a grant cookie")
		}
		if c.Name == cookieCSRF {
			csrf = c.Value
		}
	}
	if csrf == "" || !strings.Contains(w.Body.String(), `value="`+csrf+`"`) {
		t.Fatalf("form lacks CSRF token %q: %q", csrf, w.Body.String())
	}
	wantLoginRedirect(t, f.do(contentReq{host: hostOf(site), path: "/"}))
}

// V10
func TestLinkPostCSRF(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	link := f.createLink(site, `{}`)
	host := "http://" + hostOf(site)
	for name, tc := range map[string]struct {
		q    linkReq
		code int
	}{
		"wrong token":    {linkReq{csrf: "wrong"}, http.StatusForbidden},
		"foreign origin": {linkReq{origin: "https://evil.example"}, http.StatusForbidden},
		"sibling origin": {linkReq{origin: "http://" + string(f.site()) + "." + contentZone}, http.StatusForbidden},
		"null bad token": {linkReq{origin: "null", csrf: "wrong"}, http.StatusForbidden},
		"no origin":      {linkReq{}, http.StatusSeeOther},
		"same origin":    {linkReq{origin: host}, http.StatusSeeOther},
		"null origin":    {linkReq{origin: "null"}, http.StatusSeeOther},
	} {
		t.Run(name, func(t *testing.T) {
			tc.q.site, tc.q.token = site, link.token
			w := f.linkPost(tc.q)
			wantStatus(t, w, tc.code)
			if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
				t.Fatalf("Referrer-Policy %q", got)
			}
			if tc.code == http.StatusSeeOther {
				if loc := w.Header().Get("Location"); loc != "/" {
					t.Fatalf("Location %q", loc)
				}
				return
			}
			for _, c := range w.Result().Cookies() {
				if c.Name == cookieGrant {
					t.Fatal("rejected POST set a grant cookie")
				}
			}
		})
	}

	// The link route's allowance for null must not reach the password form.
	f.setPassword(site, goodPassword)
	wantStatus(t, f.login(loginReq{site: site, password: goodPassword, origin: "null"}), http.StatusForbidden)
}

// V7
func TestLinkCookieShape(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	link := f.createLink(site, `{}`)
	w := f.linkPost(linkReq{site: site, token: link.token, https: true, origin: "null"})
	wantStatus(t, w, http.StatusSeeOther)
	c := responseCookie(t, w, "__Host-"+cookieGrant)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie %+v", c)
	}
	if c.Value == link.token || len(c.Value) != 64 {
		t.Fatalf("cookie value %q", c.Value)
	}
	ctx := context.Background()
	s, err := f.db.GrantSession(ctx, site, TokenHash(c.Value), time.Now())
	if err != nil {
		t.Fatalf("session stored under hash: %v", err)
	}
	if s.Link != link.ID || s.Password != "" {
		t.Fatalf("session %+v", s)
	}
}

// V11
func TestLinkExpiryRules(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	near := func(t *testing.T, got time.Time, want time.Duration) {
		t.Helper()
		if d := time.Until(got) - want; d > time.Minute || d < -time.Minute {
			t.Fatalf("expires in %s, want %s", time.Until(got), want)
		}
	}
	const day = 24 * time.Hour
	near(t, f.createLink(site, `{}`).ExpiresAt, 7*day)
	near(t, f.createLink(site, `{"expires_in":""}`).ExpiresAt, 7*day)
	near(t, f.createLink(site, `{"expires_in":"12h"}`).ExpiresAt, 12*time.Hour)
	near(t, f.createLink(site, `{"expires_in":"365d"}`).ExpiresAt, 365*day)
	for _, bad := range []string{"366d", "8761h", "0d", "-1d", "0s", "-1h", "1s", "99999999999999999999d", "2562047h48m", "soon", "1.5d"} {
		w := f.api(http.MethodPost, f.linkPath(site), f.token, `{"expires_in":"`+bad+`"}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d", bad, w.Code)
		}
	}
}

// V11
func TestLinkSessionLengthAndReuse(t *testing.T) {
	f := newContentFixture(t)
	ctx := context.Background()
	site := f.site()

	long := f.createLink(site, `{"expires_in":"7d"}`)
	w := f.linkPost(linkReq{site: site, token: long.token})
	wantStatus(t, w, http.StatusSeeOther)
	c := responseCookie(t, w, cookieGrant)
	if c.MaxAge > int((24*time.Hour).Seconds()) || c.MaxAge < int((23*time.Hour).Seconds()) {
		t.Fatalf("MaxAge %d", c.MaxAge)
	}
	s, err := f.db.GrantSession(ctx, site, TokenHash(c.Value), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(s.ExpiresAt); left > 24*time.Hour || left < 23*time.Hour {
		t.Fatalf("session lasts %s", left)
	}

	short := f.createLink(site, `{"expires_in":"1h"}`)
	first := f.linkPost(linkReq{site: site, token: short.token})
	wantStatus(t, first, http.StatusSeeOther)
	c = responseCookie(t, first, cookieGrant)
	if c.MaxAge > int(time.Hour.Seconds()) {
		t.Fatalf("cookie outlives link: MaxAge %d", c.MaxAge)
	}
	s, err = f.db.GrantSession(ctx, site, TokenHash(c.Value), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !s.ExpiresAt.Equal(short.ExpiresAt.Truncate(time.Second)) {
		t.Fatalf("session ends %s, link ends %s", s.ExpiresAt, short.ExpiresAt)
	}

	second := f.linkSession(site, short.token)
	if second == c.Value || !f.viewerSees(site, second) || !f.viewerSees(site, c.Value) {
		t.Fatal("link not reusable")
	}
}

// V1
func TestLinkGrantsAloneAndOnlyItsSite(t *testing.T) {
	f := newContentFixture(t)
	site, other := f.site(), f.site()
	f.setPassword(site, goodPassword)
	f.setPassword(other, goodPassword)
	cookie := f.linkSession(site, f.createLink(site, `{}`).token)
	if !f.viewerSees(site, cookie) {
		t.Fatal("link session needs more than the link")
	}
	wantLoginRedirect(t, f.do(contentReq{host: hostOf(other), path: "/", cookie: cookie}))
}

// V2, V3
func TestRevokeEndsOnlyThatLinksSessions(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	a, b := f.createLink(site, `{}`), f.createLink(site, `{}`)
	byA, byB := f.linkSession(site, a.token), f.linkSession(site, b.token)
	byPassword := f.loginSession(site, goodPassword)

	wantStatus(t, f.api(http.MethodDelete, f.linkPath(site)+"/"+string(a.ID), f.token, ""), http.StatusNoContent)
	wantLoginRedirect(t, f.do(contentReq{host: hostOf(site), path: "/", cookie: byA}))
	if !f.viewerSees(site, byB) || !f.viewerSees(site, byPassword) {
		t.Fatal("revoke ended another grant's session")
	}

	wantStatus(t, f.api(http.MethodDelete, "/v1/sites/"+string(site)+"/password", f.token, ""), http.StatusNoContent)
	if !f.viewerSees(site, byB) {
		t.Fatal("clearing password ended link session")
	}
	wantLoginRedirect(t, f.do(contentReq{host: hostOf(site), path: "/", cookie: byPassword}))
}

// V3
func TestLinkSessionSurvivesRestart(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	cookie := f.linkSession(site, f.createLink(site, `{}`).token)
	restarted := New(f.srv.Host, "admintok", "https://artifacts.test")
	restarted.ContentDomain = contentZone
	f.handler = restarted.Handler()
	if !f.viewerSees(site, cookie) {
		t.Fatal("session lost across restart")
	}
}

// V5: the routes exist on content hosts only.
func TestLinkRoutesRespectContentRouter(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	link := f.createLink(site, `{}`)
	wantStatus(t, f.do(contentReq{host: "artifacts.test", path: "/__ah/link/" + link.token}), http.StatusNotFound)
	wantStatus(t, f.do(contentReq{host: hostOf(site), method: http.MethodPut, path: "/__ah/link/" + link.token}), http.StatusNotFound)
	wantStatus(t, f.do(contentReq{host: hostOf(site), path: "/v1/sites/" + string(site) + "/links"}), http.StatusSeeOther)
}
