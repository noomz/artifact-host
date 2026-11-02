package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/noomz/artifact-host/internal/domain"
)

var csrfFieldRE = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func jarClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func pageCSRF(t *testing.T, c *http.Client, page string) string {
	t.Helper()
	res, err := c.Get(page)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	m := csrfFieldRE.FindSubmatch(b)
	if m == nil {
		t.Fatalf("no csrf field on %s: %s", page, b)
	}
	return string(m[1])
}

func adminLogin(t *testing.T, c *http.Client, base, admin string) string {
	t.Helper()
	tok := pageCSRF(t, c, base+"/admin/login")
	res, err := c.PostForm(base+"/admin/login", url.Values{"token": {admin}, "csrf": {tok}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(b), "Users") {
		t.Fatalf("login %d %s", res.StatusCode, b)
	}
	return tok
}

func postOrigin(t *testing.T, c *http.Client, target, origin string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res
}

// adminFixture seeds a user with a real token, a team, a member, and a site.
// It returns every admin POST route, with logout last because it ends the session.
func adminFixture(t *testing.T, s *Server, base, admin string) (routes []string, userToken string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/users", strings.NewReader(`{"name":"ada"}`))
	req.Header.Set("Authorization", "Bearer "+admin)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	u := domain.UserID(created.ID)
	team := domain.TeamID("t1")
	if err := s.Host.Meta.CreateTeam(ctx, team, "core"); err != nil {
		t.Fatal(err)
	}
	if err := s.Host.Meta.AddMember(ctx, team, u); err != nil {
		t.Fatal(err)
	}
	pub, _ := http.NewRequest(http.MethodPost, base+"/v1/sites", tarBody(t, map[string]string{"index.html": "hi"}))
	pub.Header.Set("Authorization", "Bearer "+created.Token)
	pub.Header.Set("Visibility", "owner")
	pres, err := http.DefaultClient.Do(pub)
	if err != nil {
		t.Fatal(err)
	}
	pres.Body.Close()
	if pres.StatusCode >= 300 {
		t.Fatalf("publish %d", pres.StatusCode)
	}
	sites, err := s.Host.Meta.ListSites(ctx)
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites %v %v", sites, err)
	}
	return []string{
		"/admin/login",
		"/admin/users",
		"/admin/users/" + created.ID + "/rotate",
		"/admin/teams",
		"/admin/teams/t1/members",
		"/admin/teams/t1/members/" + created.ID + "/delete",
		"/admin/sites/" + string(sites[0].ID) + "/delete",
		"/admin/teams/t1/delete",
		"/admin/users/" + created.ID + "/delete",
		"/admin/logout",
	}, created.Token
}

func adminState(t *testing.T, s *Server) string {
	t.Helper()
	ctx := context.Background()
	users, err := s.Host.Meta.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	teams, err := s.Host.Meta.ListTeams(ctx)
	if err != nil {
		t.Fatal(err)
	}
	members, err := s.Host.Meta.Members(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	sites, err := s.Host.Meta.ListSites(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(users, teams, members, sites)
}

func TestValidateAdminToken(t *testing.T) {
	if err := ValidateAdminToken(""); err == nil {
		t.Fatal("empty")
	}
	if err := ValidateAdminToken("short"); err == nil {
		t.Fatal("short")
	}
	if err := ValidateAdminToken("replace-me"); err == nil {
		t.Fatal("placeholder")
	}
	if err := ValidateAdminToken(strings.Repeat("a", 32)); err != nil {
		t.Fatal(err)
	}
}

func TestAdminLoginAndUserToken(t *testing.T) {
	_, ts, admin := testServer(t)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{Jar: jar}

	res, err := c.Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(b), "Admin token") {
		t.Fatalf("want login page, got %d %s", res.StatusCode, b)
	}
	if res.Header.Get("X-Frame-Options") != "DENY" {
		t.Fatalf("frame options %q", res.Header.Get("X-Frame-Options"))
	}

	res, err = c.Get(ts.URL + "/admin/login?err=Session+expired+https://evil.example")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if strings.Contains(string(b), "evil.example") {
		t.Fatalf("attacker err text leaked: %s", b)
	}

	csrf := pageCSRF(t, c, ts.URL+"/admin/login")
	res, err = c.PostForm(ts.URL+"/admin/login", url.Values{"token": {"nope"}, "csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "That token was not accepted") {
		t.Fatalf("want bad token, got %s", b)
	}

	res, err = c.PostForm(ts.URL+"/admin/login", url.Values{"token": {admin}, "csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(b), "Users") {
		t.Fatalf("want dashboard, got %d %s", res.StatusCode, b)
	}
	u, _ := url.Parse(ts.URL + "/admin")
	var sawSession bool
	for _, ck := range jar.Cookies(u) {
		if ck.Name == "ah_flash" {
			t.Fatal("flash cookie must not be set")
		}
		if ck.Name == "ah_admin" && ck.Value == admin {
			t.Fatal("raw admin token in cookie")
		}
		if ck.Name == "ah_session" {
			sawSession = true
			if ck.Value == admin {
				t.Fatal("session cookie is admin token")
			}
		}
	}
	if !sawSession {
		t.Fatal("missing ah_session")
	}

	res, err = c.PostForm(ts.URL+"/admin/users", url.Values{"name": {"ada"}, "csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	body := string(b)
	if !strings.Contains(body, "New token for") || !strings.Contains(body, "ada") {
		t.Fatalf("want issued token, got %s", body)
	}
	if !strings.Contains(body, `id="tok"`) {
		t.Fatalf("missing token field: %s", body)
	}
	for _, ck := range jar.Cookies(u) {
		if ck.Name == "ah_flash" {
			t.Fatal("token must not be in a cookie")
		}
	}

	res, err = c.PostForm(ts.URL+"/admin/teams", url.Values{"name": {"core"}, "csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "core") {
		t.Fatalf("want team, got %s", b)
	}
}

func TestAdminRejectsAnonPOST(t *testing.T) {
	s, ts, _ := testServer(t)
	res, err := http.PostForm(ts.URL+"/admin/users", url.Values{"name": {"eve"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("anon without token: %d", res.StatusCode)
	}

	// A valid CSRF pair is not authentication: an expired session lands on login.
	c := jarClient(t)
	csrf := pageCSRF(t, c, ts.URL+"/admin/login")
	res, err = c.PostForm(ts.URL+"/admin/users", url.Values{"name": {"eve"}, "csrf": {csrf}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(b), "Admin token") {
		t.Fatalf("anon create should land on login, got %d %s", res.StatusCode, b)
	}
	users, err := s.Host.Meta.ListUsers(context.Background())
	if err != nil || len(users) != 0 {
		t.Fatalf("users %v %v", users, err)
	}
}

func TestAdminLoginRateLimit(t *testing.T) {
	_, ts, _ := testServer(t)
	c := jarClient(t)
	csrf := pageCSRF(t, c, ts.URL+"/admin/login")
	form := url.Values{"token": {"nope"}, "csrf": {csrf}}
	for i := 0; i < 5; i++ {
		res, err := c.PostForm(ts.URL+"/admin/login", form)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
	res, err := c.PostForm(ts.URL+"/admin/login", form)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "Too many sign-in attempts") {
		t.Fatalf("want rate limit, got %s", b)
	}
}

func TestAdminPOSTRoutesRequireCSRF(t *testing.T) {
	s, ts, admin := testServer(t)
	routes, userToken := adminFixture(t, s, ts.URL, admin)
	c := jarClient(t)
	csrf := adminLogin(t, c, ts.URL, admin)
	before := adminState(t, s)
	userID := strings.Split(routes[2], "/")[3]

	base := url.Values{"name": {"x"}, "user_id": {userID}, "token": {admin}}
	for _, route := range routes {
		for name, val := range map[string][]string{"missing": nil, "wrong": {strings.Repeat("0", 64)}, "empty": {""}} {
			form := url.Values{"name": base["name"], "user_id": base["user_id"], "token": base["token"]}
			if val != nil {
				form["csrf"] = val
			}
			if res := postOrigin(t, c, ts.URL+route, "", form); res.StatusCode != http.StatusForbidden {
				t.Fatalf("%s %s token: %d", route, name, res.StatusCode)
			}
		}
		// A token in the URL query does not count; only the POST body does.
		if res := postOrigin(t, c, ts.URL+route+"?csrf="+csrf, "", base); res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s query token: %d", route, res.StatusCode)
		}
		// Sandboxed /s/ pages send Origin: null. A valid token must not rescue it.
		form := url.Values{"name": base["name"], "user_id": base["user_id"], "token": base["token"], "csrf": {csrf}}
		if res := postOrigin(t, c, ts.URL+route, "null", form); res.StatusCode != http.StatusForbidden {
			t.Fatalf("%s null origin: %d", route, res.StatusCode)
		}
	}

	if got := adminState(t, s); got != before {
		t.Fatalf("rejected POST changed state:\n%s\n%s", before, got)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/sites", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("rejected rotate changed user token: %d", res.StatusCode)
	}
	res, err = c.Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(b), "Sign out") {
		t.Fatalf("rejected logout ended session: %s", b)
	}

	for _, route := range routes {
		form := url.Values{"name": base["name"], "user_id": base["user_id"], "token": base["token"], "csrf": {csrf}}
		if res := postOrigin(t, c, ts.URL+route, ts.URL, form); res.StatusCode == http.StatusForbidden {
			t.Fatalf("%s same origin with token: 403", route)
		}
	}
}

func TestAdminCSRFRejectsEmptyCookie(t *testing.T) {
	s, _, _ := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "http://localhost:8080/admin/login", strings.NewReader("csrf=&token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "ah_csrf", Value: ""})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("empty cookie and field: %d", rec.Code)
	}
}

func TestAdminFormsCarryCSRF(t *testing.T) {
	s, ts, admin := testServer(t)
	adminFixture(t, s, ts.URL, admin)
	c := jarClient(t)
	for _, page := range []string{"/admin/login", "/admin"} {
		res, err := c.Get(ts.URL + page)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		forms := strings.Count(string(b), "<form")
		fields := len(csrfFieldRE.FindAll(b, -1))
		if forms == 0 || forms != fields {
			t.Fatalf("%s: %d forms, %d csrf fields: %s", page, forms, fields, b)
		}
		if page == "/admin/login" {
			adminLogin(t, c, ts.URL, admin)
		}
	}
	res, err := c.Get(ts.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	// Forms inside each range: rotate, delete user, member, remove, delete site.
	for _, action := range []string{"/rotate", "/members/", "/admin/sites/"} {
		if !strings.Contains(string(b), action) {
			t.Fatalf("dashboard missing %s: %s", action, b)
		}
	}
	if !strings.HasSuffix(strings.TrimSpace(string(b)), "</main>") {
		t.Fatalf("dashboard render stopped early: %s", b)
	}
}

func TestAdminCSRFOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin func(ts string) string
		want   bool
	}{
		{"absent", func(string) string { return "" }, true},
		{"same origin", func(ts string) string { return ts }, true},
		{"null", func(string) string { return "null" }, false},
		{"other site", func(string) string { return "https://evil.example" }, false},
		{"sibling subdomain", func(ts string) string { return strings.Replace(ts, "http://", "http://abc.u.", 1) }, false},
		{"other scheme", func(ts string) string { return strings.Replace(ts, "http://", "https://", 1) }, false},
		{"other port", func(ts string) string { return ts + "1" }, false},
		{"suffix attack", func(ts string) string { return ts + ".evil.example" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, ts, admin := testServer(t)
			c := jarClient(t)
			csrf := adminLogin(t, c, ts.URL, admin)
			res := postOrigin(t, c, ts.URL+"/admin/teams", tc.origin(ts.URL), url.Values{"name": {"core"}, "csrf": {csrf}})
			teams, err := s.Host.Meta.ListTeams(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if tc.want && (res.StatusCode != 200 || len(teams) != 1) {
				t.Fatalf("want accepted, got %d, teams %v", res.StatusCode, teams)
			}
			if !tc.want && (res.StatusCode != http.StatusForbidden || len(teams) != 0) {
				t.Fatalf("want 403, got %d, teams %v", res.StatusCode, teams)
			}
		})
	}
}

func TestAdminBearerNeedsNoCSRF(t *testing.T) {
	s, ts, admin := testServer(t)
	post := func(tok string) int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/teams", strings.NewReader("name=core"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+tok)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if got := post(strings.Repeat("x", len(admin))); got != http.StatusForbidden {
		t.Fatalf("bad bearer: %d", got)
	}
	if got := post(admin); got != 200 {
		t.Fatalf("admin bearer: %d", got)
	}
	teams, err := s.Host.Meta.ListTeams(context.Background())
	if err != nil || len(teams) != 1 {
		t.Fatalf("teams %v %v", teams, err)
	}
}

func cookieNamed(t *testing.T, res *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, ck := range res.Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	t.Fatalf("no %s in %v", name, res.Header["Set-Cookie"])
	return nil
}

func TestAdminCookiesOverHTTPS(t *testing.T) {
	s, _, admin := testServer(t)
	h := s.Handler()
	const origin = "https://artifacts.test"
	do := func(method, path, body string, cookies ...*http.Cookie) *http.Response {
		req := httptest.NewRequest(method, "http://artifacts.test"+path, strings.NewReader(body))
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("Origin", origin)
		if body != "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for _, ck := range cookies {
			req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Result()
	}

	res := do(http.MethodGet, "/admin/login", "")
	body, _ := io.ReadAll(res.Body)
	csrf := cookieNamed(t, res, "__Host-ah_csrf")
	if !csrf.Secure || csrf.Path != "/" || csrf.Domain != "" || !csrf.HttpOnly || csrf.SameSite != http.SameSiteLaxMode {
		t.Fatalf("csrf cookie %+v", csrf)
	}
	if m := csrfFieldRE.FindSubmatch(body); m == nil || string(m[1]) != csrf.Value {
		t.Fatalf("form token does not match cookie: %s", body)
	}
	form := "csrf=" + csrf.Value + "&token=" + admin

	// An unprefixed cookie can be tossed by a sibling host, so HTTPS must ignore it.
	tossed := &http.Cookie{Name: "ah_csrf", Value: csrf.Value}
	if got := do(http.MethodPost, "/admin/login", form, tossed); got.StatusCode != http.StatusForbidden {
		t.Fatalf("unprefixed csrf cookie over https: %d", got.StatusCode)
	}

	res = do(http.MethodPost, "/admin/login", form, csrf)
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login %d", res.StatusCode)
	}
	sess := cookieNamed(t, res, "__Host-ah_session")
	if !sess.Secure || sess.Path != "/" || sess.Domain != "" || !sess.HttpOnly || sess.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie %+v", sess)
	}

	if got := do(http.MethodGet, "/admin", "", sess); got.StatusCode != 200 {
		t.Fatalf("dashboard %d", got.StatusCode)
	}
	if got := do(http.MethodGet, "/admin", "", &http.Cookie{Name: "ah_session", Value: sess.Value}); got.StatusCode != http.StatusSeeOther {
		t.Fatalf("unprefixed session over https: %d", got.StatusCode)
	}

	res = do(http.MethodPost, "/admin/logout", "csrf="+csrf.Value, csrf, sess)
	cleared := cookieNamed(t, res, "__Host-ah_session")
	if cleared.MaxAge >= 0 || !cleared.Secure || cleared.Path != "/" {
		t.Fatalf("logout cookie %+v", cleared)
	}
	if got := do(http.MethodGet, "/admin", "", sess); got.StatusCode != http.StatusSeeOther {
		t.Fatalf("session after logout: %d", got.StatusCode)
	}
}

func TestAdminCookiesOverPlainHTTP(t *testing.T) {
	s, _, admin := testServer(t)
	h := s.Handler()
	do := func(method, path, body string, cookies ...*http.Cookie) *http.Response {
		req := httptest.NewRequest(method, "http://localhost:8080"+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		for _, ck := range cookies {
			req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Result()
	}
	csrf := cookieNamed(t, do(http.MethodGet, "/admin/login", ""), "ah_csrf")
	if csrf.Secure {
		t.Fatalf("csrf cookie %+v", csrf)
	}
	res := do(http.MethodPost, "/admin/login", "csrf="+csrf.Value+"&token="+admin, csrf)
	sess := cookieNamed(t, res, "ah_session")
	if sess.Secure {
		t.Fatalf("session cookie %+v", sess)
	}
	if got := do(http.MethodGet, "/admin", "", sess); got.StatusCode != 200 {
		t.Fatalf("dashboard %d", got.StatusCode)
	}
	prefixed := &http.Cookie{Name: "__Host-ah_session", Value: sess.Value}
	if got := do(http.MethodGet, "/admin", "", prefixed); got.StatusCode != http.StatusSeeOther {
		t.Fatalf("prefixed session over http: %d", got.StatusCode)
	}
}
