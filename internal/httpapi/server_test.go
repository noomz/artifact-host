package httpapi

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestHTTPPublishRejectsOversizedBody(t *testing.T) {
	const block = 512
	tests := []struct {
		name  string
		sizes []int64
	}{
		{"limit cuts inside an entry", []int64{maxBody + block}},
		{"limit falls exactly between entries", []int64{maxBody - 3*block, 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, ts, admin := testServer(t)
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/users", bytes.NewBufferString(`{"name":"ada"}`))
			req.Header.Set("Authorization", "Bearer "+admin)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			var created struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			write := func(name string, size int64) {
				if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: size}); err != nil {
					t.Fatal(err)
				}
				if _, err := tw.Write(make([]byte, size)); err != nil {
					t.Fatal(err)
				}
			}
			write("index.html", 1)
			for i, size := range tc.sizes {
				write("f"+strconv.Itoa(i), size)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}

			pub, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sites", &buf)
			pub.Header.Set("Authorization", "Bearer "+created.Token)
			pub.Header.Set("Visibility", "owner")
			pres, err := http.DefaultClient.Do(pub)
			if err != nil {
				t.Fatal(err)
			}
			defer pres.Body.Close()
			b, _ := io.ReadAll(pres.Body)
			if pres.StatusCode != http.StatusRequestEntityTooLarge {
				t.Fatalf("publish %d %s", pres.StatusCode, b)
			}
			if !strings.Contains(string(b), "32 MiB") {
				t.Fatalf("message %q", b)
			}
		})
	}
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

func TestHTTPRepublishWithoutVisibilityKeepsSitePrivate(t *testing.T) {
	s, ts, _ := testServer(t)
	if err := s.Host.Meta.CreateUser(context.Background(), "u1", "ada", TokenHash("usertok")); err != nil {
		t.Fatal(err)
	}
	publish := func(siteID, vis, body string) string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/sites", tarBody(t, map[string]string{"index.html": body}))
		req.Header.Set("Authorization", "Bearer usertok")
		if siteID != "" {
			req.Header.Set("Site-Id", siteID)
		}
		if vis != "" {
			req.Header.Set("Visibility", vis)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("publish %d %s", res.StatusCode, b)
		}
		var out struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out.ID
	}
	id := publish("", "owner", "v1")
	publish(id, "", "v2")

	anon, err := http.Get(ts.URL + "/s/" + id + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anon get %d", anon.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/s/"+id+"/", nil)
	req.Header.Set("Authorization", "Bearer usertok")
	owner, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Body.Close()
	b, _ := io.ReadAll(owner.Body)
	if owner.StatusCode != http.StatusOK || string(b) != "v2" {
		t.Fatalf("owner get %d %q", owner.StatusCode, b)
	}
}
