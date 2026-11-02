package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/noomz/artifact-host/internal/httpapi"
)

func withContentDomain(t *testing.T, srv *httpapi.Server) {
	t.Helper()
	srv.ContentDomain = "u.test"
	server := httptest.NewServer(srv.Handler())
	t.Cleanup(server.Close)
	t.Setenv("ARTIFACT_HOST_URL", server.URL)
}

func captureStdout(t *testing.T, run func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	code := run()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), code
}

func TestLinkCreateAndRevoke(t *testing.T) {
	host, site := passwordFixture(t)
	withContentDomain(t, httpapi.New(host, "admin", "https://artifacts.test"))
	ctx := context.Background()

	out, code := captureStdout(t, func() int {
		return Main([]string{"link", "create", string(site), "--label", "for Ada", "--expires", "2d"})
	})
	if code != 0 {
		t.Fatalf("create exit %d", code)
	}
	var created struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("output %q: %v", out, err)
	}
	if !strings.HasPrefix(created.URL, "https://"+string(site)+".u.test/__ah/link/") {
		t.Fatalf("url %q", created.URL)
	}
	links, err := host.Meta.SiteLinks(ctx, site)
	if err != nil || len(links) != 1 {
		t.Fatalf("links %+v %v", links, err)
	}
	if links[0].Label != "for Ada" {
		t.Fatalf("label %q", links[0].Label)
	}
	if left := time.Until(links[0].ExpiresAt); left > 48*time.Hour || left < 47*time.Hour {
		t.Fatalf("expires in %s", left)
	}

	if code := Main([]string{"link", "revoke", string(site), created.ID}); code != 0 {
		t.Fatalf("revoke exit %d", code)
	}
	if links, err := host.Meta.SiteLinks(ctx, site); err != nil || len(links) != 0 {
		t.Fatalf("after revoke: %+v %v", links, err)
	}
}

func TestLinkRefusals(t *testing.T) {
	host, site := passwordFixture(t)
	withContentDomain(t, httpapi.New(host, "admin", "https://artifacts.test"))
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"no action", []string{"link"}, 2},
		{"unknown action", []string{"link", "show", string(site)}, 2},
		{"create without site", []string{"link", "create"}, 2},
		{"create extra argument", []string{"link", "create", string(site), "extra"}, 2},
		{"revoke without link", []string{"link", "revoke", string(site)}, 2},
		{"revoke with create flag", []string{"link", "revoke", string(site), "id", "--label", "x"}, 2},
		{"expiry too long", []string{"link", "create", string(site), "--expires", "366d"}, 1},
		{"revoke unknown link", []string{"link", "revoke", string(site), "nope"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := Main(tc.args); code != tc.code {
				t.Fatalf("exit %d, want %d", code, tc.code)
			}
		})
	}
	if links, err := host.Meta.SiteLinks(context.Background(), site); err != nil || len(links) != 0 {
		t.Fatalf("links stored: %+v %v", links, err)
	}
}
