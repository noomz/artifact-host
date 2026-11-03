package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/sites"
)

const mainHost = "artifacts.test"

type accessResult struct {
	HasPassword bool `json:"has_password"`
	Links       []struct {
		ID        domain.LinkID `json:"id"`
		Label     string        `json:"label"`
		CreatedAt time.Time     `json:"created_at"`
		ExpiresAt time.Time     `json:"expires_at"`
	} `json:"links"`
	ContentURL string `json:"content_url"`
}

func (f *contentFixture) access(site domain.SiteID) (accessResult, string) {
	f.t.Helper()
	w := f.api(http.MethodGet, "/v1/sites/"+string(site)+"/access", f.token, "")
	wantStatus(f.t, w, http.StatusOK)
	var a accessResult
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
		f.t.Fatal(err)
	}
	return a, w.Body.String()
}

func (f *contentFixture) anon(path string) *httptest.ResponseRecorder {
	f.t.Helper()
	return f.do(contentReq{host: mainHost, path: path})
}

func sitePath(site domain.SiteID, rest string) string {
	return "/s/" + string(site) + rest
}

// V4
func TestAccessOnlyOwnerReads(t *testing.T) {
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
	out, err := f.srv.Host.Publish(ctx, f.owner, sites.PublishIn{
		Visibility: domain.VisTeam,
		Team:       "team",
		Files:      []domain.File{{Path: "index.html", Body: []byte("x")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/sites/" + string(out.Site) + "/access"
	wantStatus(t, f.api(http.MethodGet, path, "owner-token", ""), http.StatusOK)
	wantStatus(t, f.api(http.MethodGet, path, "member-token", ""), http.StatusForbidden)
	wantStatus(t, f.api(http.MethodGet, path, "other-token", ""), http.StatusForbidden)
	wantStatus(t, f.api(http.MethodGet, path, "admintok", ""), http.StatusForbidden)
	wantStatus(t, f.api(http.MethodGet, path, "", ""), http.StatusUnauthorized)
	wantStatus(t, f.api(http.MethodGet, "/v1/sites/"+strings.Repeat("0", 32)+"/access", "owner-token", ""), http.StatusNotFound)
}

func TestAccessReportsEachGrantState(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()

	a, raw := f.access(site)
	if a.HasPassword || len(a.Links) != 0 {
		t.Fatalf("no grants: %s", raw)
	}
	if !strings.Contains(raw, `"links":[]`) {
		t.Fatalf("links must be an empty list: %s", raw)
	}
	if want := "https://" + hostOf(site) + "/"; a.ContentURL != want {
		t.Fatalf("content_url %q, want %q", a.ContentURL, want)
	}

	f.setPassword(site, goodPassword)
	if a, raw = f.access(site); !a.HasPassword || len(a.Links) != 0 {
		t.Fatalf("password only: %s", raw)
	}

	l := f.createLink(site, `{"label":"for Ada"}`)
	a, raw = f.access(site)
	if !a.HasPassword || len(a.Links) != 1 {
		t.Fatalf("both: %s", raw)
	}
	got := a.Links[0]
	if got.ID != l.ID || got.Label != "for Ada" || got.CreatedAt.IsZero() || got.ExpiresAt.Unix() != l.ExpiresAt.Unix() {
		t.Fatalf("link %+v, created %+v", got, l)
	}

	wantStatus(t, f.api(http.MethodDelete, "/v1/sites/"+string(site)+"/password", f.token, ""), http.StatusNoContent)
	if a, raw = f.access(site); a.HasPassword || len(a.Links) != 1 {
		t.Fatalf("link only: %s", raw)
	}
}

func TestAccessListsExpiredLinks(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.expiredLink(site)
	a, raw := f.access(site)
	if len(a.Links) != 1 || a.Links[0].ExpiresAt.After(time.Now()) {
		t.Fatalf("expired link: %s", raw)
	}
}

func TestAccessWithoutContentDomain(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.srv.ContentDomain = ""
	f.handler = f.srv.Handler()
	a, raw := f.access(site)
	if a.ContentURL != "" {
		t.Fatalf("content_url without domain: %s", raw)
	}
}

// V8
func TestAccessHoldsNoSecrets(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	l := f.createLink(site, `{"label":"x"}`)
	w := f.api(http.MethodGet, "/v1/sites/"+string(site)+"/access", f.token, "")
	wantStatus(t, w, http.StatusOK)
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control %q", got)
	}
	for _, secret := range []string{goodPassword, l.token, "argon2", "hash", "token"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("response holds %q: %s", secret, w.Body)
		}
	}
}

// V13
func TestServeRedirectsAnonymousToContentHost(t *testing.T) {
	f := newContentFixture(t)
	password := f.site()
	f.password(password)
	link := f.site()
	f.link(link)
	both := f.site()
	f.password(both)
	f.link(both)

	for name, site := range map[string]domain.SiteID{"password": password, "link": link, "both": both} {
		t.Run(name, func(t *testing.T) {
			w := f.anon(sitePath(site, "/"))
			wantStatus(t, w, http.StatusFound)
			if got, want := w.Header().Get("Location"), "https://"+hostOf(site)+"/"; got != want {
				t.Fatalf("Location %q, want %q", got, want)
			}
			if got := w.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control %q", got)
			}
		})
	}
}

func TestServeRedirectKeepsPathAndQuery(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.password(site)
	root := "https://" + hostOf(site)
	for _, tc := range []struct{ rest, want string }{
		{"", root + "/"},
		{"/", root + "/"},
		{"/a/b.html", root + "/a/b.html"},
		{"/a/b.html?x=1&y=2", root + "/a/b.html?x=1&y=2"},
		{"/?x=1", root + "/?x=1"},
		{"/a%20b.html", root + "/a%20b.html"},
		{"/a%3Fb.html", root + "/a%3Fb.html"},
	} {
		t.Run(tc.rest, func(t *testing.T) {
			w := f.anon(sitePath(site, tc.rest))
			wantStatus(t, w, http.StatusFound)
			if got := w.Header().Get("Location"); got != tc.want {
				t.Fatalf("Location %q, want %q", got, tc.want)
			}
		})
	}
}

func TestServeRedirectStaysOnContentHost(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.password(site)
	for _, rest := range []string{
		"/%2F%2Fevil.example/x",
		"/%5C%5Cevil.example/x",
		"/%2F..%2F..%2Fevil.example",
		"/@evil.example",
		"/x?next=https://evil.example",
	} {
		t.Run(rest, func(t *testing.T) {
			w := f.anon(sitePath(site, rest))
			wantStatus(t, w, http.StatusFound)
			u, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if u.Scheme != "https" || u.Host != hostOf(site) {
				t.Fatalf("Location %q left the content host", w.Header().Get("Location"))
			}
		})
	}
}

func TestServeRedirectForPercentEncodedID(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.password(site)
	encoded := fmt.Sprintf("%%%02x", string(site)[0]) + string(site)[1:]
	w := f.anon("/s/" + encoded + "/a.html")
	wantStatus(t, w, http.StatusFound)
	if got, want := w.Header().Get("Location"), "https://"+hostOf(site)+"/a.html"; got != want {
		t.Fatalf("Location %q, want %q", got, want)
	}
}

func TestServeRedirectKeepsBaseSchemeAndPort(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.password(site)
	f.srv.BaseURL = "http://localhost:8080"
	w := f.anon(sitePath(site, "/a.html"))
	wantStatus(t, w, http.StatusFound)
	if got, want := w.Header().Get("Location"), "http://"+hostOf(site)+":8080/a.html"; got != want {
		t.Fatalf("Location %q, want %q", got, want)
	}
}

func TestServeWithoutActiveGrantRespondsAsBefore(t *testing.T) {
	f := newContentFixture(t)
	none := f.site()
	expired := f.site()
	f.expiredLink(expired)
	pub, err := f.srv.Host.Publish(context.Background(), f.owner, sites.PublishIn{
		Visibility: domain.VisPublic,
		Files:      []domain.File{{Path: "index.html", Body: []byte("public home")}},
	})
	if err != nil {
		t.Fatal(err)
	}

	wantStatus(t, f.anon(sitePath(none, "/")), http.StatusUnauthorized)
	wantStatus(t, f.anon(sitePath(expired, "/")), http.StatusUnauthorized)
	wantStatus(t, f.anon("/s/"+strings.Repeat("0", 32)+"/"), http.StatusNotFound)
	w := f.anon(sitePath(pub.Site, "/"))
	wantStatus(t, w, http.StatusOK)
	if w.Body.String() != "public home" {
		t.Fatalf("public body %q", w.Body)
	}
}

func TestServeNoRedirectWithoutContentDomain(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.password(site)
	f.srv.ContentDomain = ""
	f.handler = f.srv.Handler()
	wantStatus(t, f.anon(sitePath(site, "/")), http.StatusUnauthorized)
}

func TestServeBearerNotRedirected(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.password(site)
	path := sitePath(site, "/")
	w := f.do(contentReq{host: mainHost, path: path, bearer: "owner-token"})
	wantStatus(t, w, http.StatusOK)
	if w.Body.String() != "site home" {
		t.Fatalf("owner body %q", w.Body)
	}
	if got := w.Header().Get("Content-Security-Policy"); !strings.HasPrefix(got, "sandbox") {
		t.Fatalf("owner read lost sandbox: %q", got)
	}
	wantStatus(t, f.do(contentReq{host: mainHost, path: path, bearer: "other-token"}), http.StatusForbidden)
	wantStatus(t, f.do(contentReq{host: mainHost, path: path, bearer: "no-such-token"}), http.StatusUnauthorized)
}

// V3, V13
func TestServeRedirectStopsWhenGrantEnds(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	l := f.createLink(site, `{}`)
	path := sitePath(site, "/")
	wantStatus(t, f.anon(path), http.StatusFound)

	wantStatus(t, f.api(http.MethodDelete, "/v1/sites/"+string(site)+"/password", f.token, ""), http.StatusNoContent)
	wantStatus(t, f.anon(path), http.StatusFound)

	wantStatus(t, f.api(http.MethodDelete, f.linkPath(site)+"/"+string(l.ID), f.token, ""), http.StatusNoContent)
	wantStatus(t, f.anon(path), http.StatusUnauthorized)
}

// V4
func TestAdminDashboardShowsGrantState(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	bare := f.site()
	f.setPassword(site, goodPassword)
	l := f.createLink(site, `{"label":"<b>for Ada"}`)
	expired := f.expiredLink(site)

	w := f.api(http.MethodGet, "/admin", "admintok", "")
	wantStatus(t, w, http.StatusOK)
	page := w.Body.String()
	for _, want := range []string{
		"/admin/sites/" + string(site) + "/password/delete",
		"/admin/sites/" + string(site) + "/links/" + string(l.ID) + "/delete",
		"&lt;b&gt;for Ada",
		"expired",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("dashboard missing %q: %s", want, page)
		}
	}
	if strings.Contains(page, "/admin/sites/"+string(bare)+"/password/delete") {
		t.Fatalf("clear offered for a site with no password: %s", page)
	}
	for _, secret := range []string{goodPassword, l.token, expired, "argon2", "<b>for Ada"} {
		if strings.Contains(page, secret) {
			t.Fatalf("dashboard holds %q: %s", secret, page)
		}
	}
}

// V2, V3, V4
func TestAdminClearPasswordEndsOnlyPasswordSessions(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	password := f.loginSession(site, goodPassword)
	link := f.session(domain.GrantSession{Site: site, Link: f.link(site)})

	w := f.api(http.MethodPost, "/admin/sites/"+string(site)+"/password/delete", "admintok", "")
	wantStatus(t, w, http.StatusSeeOther)
	if got := w.Header().Get("Location"); got != "/admin" {
		t.Fatalf("Location %q", got)
	}
	if f.viewerSees(site, password) {
		t.Fatal("password session still works")
	}
	if !f.viewerSees(site, link) {
		t.Fatal("clearing password ended link session")
	}
	if a, raw := f.access(site); a.HasPassword || len(a.Links) != 1 {
		t.Fatalf("after clear: %s", raw)
	}
}

// V2, V3, V4
func TestAdminRevokeLinkEndsOnlyThatLink(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	password := f.loginSession(site, goodPassword)
	gone, kept := f.link(site), f.link(site)
	goneSession := f.session(domain.GrantSession{Site: site, Link: gone})
	keptSession := f.session(domain.GrantSession{Site: site, Link: kept})

	wantStatus(t, f.api(http.MethodPost, "/admin/sites/"+string(site)+"/links/"+string(gone)+"/delete", "admintok", ""), http.StatusSeeOther)
	if f.viewerSees(site, goneSession) {
		t.Fatal("revoked link session still works")
	}
	if !f.viewerSees(site, keptSession) {
		t.Fatal("revoke ended another link's session")
	}
	if !f.viewerSees(site, password) {
		t.Fatal("revoke ended password session")
	}
}

func TestAdminRevokeRefusesLinkOfAnotherSite(t *testing.T) {
	f := newContentFixture(t)
	site, other := f.site(), f.site()
	link := f.link(site)
	w := f.api(http.MethodPost, "/admin/sites/"+string(other)+"/links/"+string(link)+"/delete", "admintok", "")
	wantStatus(t, w, http.StatusSeeOther)
	if got := w.Header().Get("Location"); !strings.Contains(got, "err=") {
		t.Fatalf("Location %q", got)
	}
	if a, raw := f.access(site); len(a.Links) != 1 {
		t.Fatalf("link removed through another site: %s", raw)
	}
}

// V4: a user token, even the owner's, is not an admin credential.
func TestAdminGrantRoutesRefuseUserToken(t *testing.T) {
	f := newContentFixture(t)
	site := f.site()
	f.setPassword(site, goodPassword)
	link := f.link(site)
	for _, path := range []string{
		"/admin/sites/" + string(site) + "/password/delete",
		"/admin/sites/" + string(site) + "/links/" + string(link) + "/delete",
	} {
		w := f.api(http.MethodPost, path, f.token, "")
		if w.Code == http.StatusSeeOther && w.Header().Get("Location") == "/admin" {
			t.Fatalf("%s accepted a user token", path)
		}
	}
	if a, raw := f.access(site); !a.HasPassword || len(a.Links) != 1 {
		t.Fatalf("grants changed: %s", raw)
	}
}
