package httpapi

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

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

	res, err = c.PostForm(ts.URL+"/admin/login", url.Values{"token": {"nope"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(b), "bad token") {
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

	res, err = c.PostForm(ts.URL+"/admin/users", url.Values{"name": {"ada"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	body := string(b)
	if !strings.Contains(body, "New token for") || !strings.Contains(body, "ada") {
		t.Fatalf("want flashed token, got %s", body)
	}
	if !strings.Contains(body, `id="tok"`) {
		t.Fatalf("missing token field: %s", body)
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
