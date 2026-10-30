package httpapi

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/noomz/artifact-host/internal/blob"
	"github.com/noomz/artifact-host/internal/meta"
	"github.com/noomz/artifact-host/internal/sites"
)

func testServer(t *testing.T) (*Server, *httptest.Server, string) {
	t.Helper()
	db, err := meta.Open("file:http-" + t.Name() + "?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h := sites.New(db, blob.NewMemory())
	s := New(h, "admintok", "http://test")
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	s.BaseURL = ts.URL
	return s, ts, "admintok"
}

func tarBody(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		b := []byte(body)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(b))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestHTTPPublishAndGet(t *testing.T) {
	_, ts, admin := testServer(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/users", bytes.NewBufferString(`{"name":"ada"}`))
	req.Header.Set("Authorization", "Bearer "+admin)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("user %d %s", res.StatusCode, b)
	}
	var created struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	pub, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sites", tarBody(t, map[string]string{"index.html": "<p>ok</p>"}))
	pub.Header.Set("Authorization", "Bearer "+created.Token)
	pub.Header.Set("Visibility", "public")
	pres, err := http.DefaultClient.Do(pub)
	if err != nil {
		t.Fatal(err)
	}
	defer pres.Body.Close()
	if pres.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(pres.Body)
		t.Fatalf("publish %d %s", pres.StatusCode, b)
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(pres.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	gres, err := http.Get(out.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer gres.Body.Close()
	if gres.StatusCode != 200 {
		t.Fatalf("get %d", gres.StatusCode)
	}
	if !strings.Contains(gres.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("csp %q", gres.Header.Get("Content-Security-Policy"))
	}
	b, _ := io.ReadAll(gres.Body)
	if string(b) != "<p>ok</p>" {
		t.Fatalf("body %q", b)
	}
}

func TestHTTPPrivateUnauthorized(t *testing.T) {
	s, ts, admin := testServer(t)
	ctx := context.Background()
	hash := TokenHash("usertok")
	if err := s.Host.Meta.CreateUser(ctx, "u1", "ada", hash); err != nil {
		t.Fatal(err)
	}
	pub, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sites", tarBody(t, map[string]string{"index.html": "secret"}))
	pub.Header.Set("Authorization", "Bearer usertok")
	pub.Header.Set("Visibility", "owner")
	pres, err := http.DefaultClient.Do(pub)
	if err != nil {
		t.Fatal(err)
	}
	defer pres.Body.Close()
	if pres.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(pres.Body)
		t.Fatalf("publish %d %s", pres.StatusCode, b)
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(pres.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	gres, err := http.Get(out.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer gres.Body.Close()
	if gres.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anon get %d", gres.StatusCode)
	}
	greq, _ := http.NewRequest(http.MethodGet, out.URL, nil)
	greq.Header.Set("Authorization", "Bearer usertok")
	ok, err := http.DefaultClient.Do(greq)
	if err != nil {
		t.Fatal(err)
	}
	defer ok.Body.Close()
	if ok.StatusCode != 200 {
		t.Fatalf("owner get %d", ok.StatusCode)
	}
	_ = admin
}
