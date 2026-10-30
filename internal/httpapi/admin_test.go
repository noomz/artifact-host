package httpapi

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

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

	res, err = c.PostForm(ts.URL+"/admin/login", url.Values{"token": {"nope"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "That token was not accepted") {
		t.Fatalf("want bad token, got %s", b)
	}

	res, err = c.PostForm(ts.URL+"/admin/login", url.Values{"token": {admin}})
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

	res, err = c.PostForm(ts.URL+"/admin/users", url.Values{"name": {"ada"}})
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

	res, err = c.PostForm(ts.URL+"/admin/teams", url.Values{"name": {"core"}})
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
	_, ts, _ := testServer(t)
	res, err := http.PostForm(ts.URL+"/admin/users", url.Values{"name": {"eve"}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(b), "Admin token") {
		t.Fatalf("anon create should land on login, got %d %s", res.StatusCode, b)
	}
}

func TestAdminLoginRateLimit(t *testing.T) {
	_, ts, _ := testServer(t)
	for i := 0; i < 5; i++ {
		res, err := http.PostForm(ts.URL+"/admin/login", url.Values{"token": {"nope"}})
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
	res, err := http.PostForm(ts.URL+"/admin/login", url.Values{"token": {"nope"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "Too many sign-in attempts") {
		t.Fatalf("want rate limit, got %s", b)
	}
}
