package cli

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/noomz/artifact-host/internal/blob"
	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/httpapi"
	"github.com/noomz/artifact-host/internal/meta"
	"github.com/noomz/artifact-host/internal/sites"
)

func passwordFixture(t *testing.T) (*sites.Host, domain.SiteID) {
	t.Helper()
	db, err := meta.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := db.CreateUser(ctx, "alice", "Alice", httpapi.TokenHash("token")); err != nil {
		t.Fatal(err)
	}
	host := sites.New(db, blob.NewMemory())
	out, err := host.Publish(ctx, domain.Principal{User: "alice"}, sites.PublishIn{
		Visibility: domain.VisOwner,
		Files:      []domain.File{{Path: "index.html", Body: []byte("x")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	withContentDomain(t, httpapi.New(host, "admin", "https://artifacts.test"))
	t.Setenv("ARTIFACT_HOST_TOKEN", "token")
	return host, out.Site
}

func withStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = old
		_ = r.Close()
	})
}

func TestPasswordSetFromStdinAndClear(t *testing.T) {
	host, site := passwordFixture(t)
	ctx := context.Background()

	withStdin(t, "first password\n")
	if code := Main([]string{"password", "set", string(site), "--stdin"}); code != 0 {
		t.Fatalf("set exit %d", code)
	}
	if _, err := host.VerifyPassword(ctx, site, "first password"); err != nil {
		t.Fatalf("trailing newline kept: %v", err)
	}

	withStdin(t, " second password \r\n")
	if code := Main([]string{"password", "set", "--stdin", string(site)}); code != 0 {
		t.Fatalf("set exit %d", code)
	}
	if _, err := host.VerifyPassword(ctx, site, " second password "); err != nil {
		t.Fatalf("spaces not kept: %v", err)
	}

	if code := Main([]string{"password", "clear", string(site)}); code != 0 {
		t.Fatalf("clear exit %d", code)
	}
	if _, err := host.Meta.SitePassword(ctx, site); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("after clear: %v", err)
	}
}

func TestPasswordSetRefusals(t *testing.T) {
	host, site := passwordFixture(t)
	for _, tc := range []struct {
		name  string
		args  []string
		stdin string
		code  int
	}{
		{"value as flag", []string{"password", "set", string(site), "--password", "hunter2hunter2"}, "", 2},
		{"value as argument", []string{"password", "set", string(site), "hunter2hunter2"}, "", 2},
		{"no site", []string{"password", "set", "--stdin"}, "", 2},
		{"unknown action", []string{"password", "show", string(site)}, "", 2},
		{"clear with stdin", []string{"password", "clear", string(site), "--stdin"}, "", 2},
		{"prompt without terminal", []string{"password", "set", string(site)}, "hunter2hunter2\n", 1},
		{"too short", []string{"password", "set", string(site), "--stdin"}, "short\n", 1},
		{"too long", []string{"password", "set", string(site), "--stdin"}, strings.Repeat("a", 5000), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withStdin(t, tc.stdin)
			if code := Main(tc.args); code != tc.code {
				t.Fatalf("exit %d, want %d", code, tc.code)
			}
			if _, err := host.Meta.SitePassword(context.Background(), site); !errors.Is(err, domain.ErrNotFound) {
				t.Fatalf("password stored: %v", err)
			}
		})
	}
}

func TestPasswordRefusedForNonOwnerToken(t *testing.T) {
	host, site := passwordFixture(t)
	if err := host.Meta.CreateUser(context.Background(), "bob", "Bob", httpapi.TokenHash("bob-token")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTIFACT_HOST_TOKEN", "bob-token")
	withStdin(t, "the password\n")
	if code := Main([]string{"password", "set", string(site), "--stdin"}); code != 1 {
		t.Fatalf("exit %d", code)
	}
}

func TestParseInterspersed(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	label := fs.String("label", "", "")
	got, err := parseInterspersed(fs, []string{"a", "--label", "L", "b"})
	if err != nil || *label != "L" || !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("%v %q %v", got, *label, err)
	}
}
