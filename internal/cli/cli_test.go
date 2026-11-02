package cli

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/noomz/artifact-host/internal/blob"
	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/httpapi"
	"github.com/noomz/artifact-host/internal/meta"
	"github.com/noomz/artifact-host/internal/sites"
)

func TestPublishListAndRename(t *testing.T) {
	db, err := meta.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.CreateUser(context.Background(), "alice", "Alice", httpapi.TokenHash("token")); err != nil {
		t.Fatal(err)
	}
	server := httpapi.New(sites.New(db, blob.NewMemory()), "admin", "")
	ts := httptest.NewServer(server.Handler())
	defer ts.Close()
	server.BaseURL = ts.URL
	t.Setenv("ARTIFACT_HOST_URL", ts.URL)
	t.Setenv("ARTIFACT_HOST_TOKEN", "token")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := Main([]string{"publish", "--name", " Café ", "--visibility", "owner", dir}); code != 0 {
		t.Fatalf("publish exit %d", code)
	}
	items, err := db.ListSites(context.Background())
	if err != nil || len(items) != 1 || items[0].Name != "Café" {
		t.Fatalf("items %+v %v", items, err)
	}
	if code := Main([]string{"list", "--scope", "owned", "--name", "CAFÉ"}); code != 0 {
		t.Fatalf("list exit %d", code)
	}
	if code := Main([]string{"rename", string(items[0].ID), "renamed"}); code != 0 {
		t.Fatalf("rename exit %d", code)
	}
	site, err := db.Site(context.Background(), items[0].ID)
	if err != nil || site.Name != "renamed" {
		t.Fatalf("site %+v %v", site, err)
	}
	if code := Main([]string{"publish", "--site", string(items[0].ID), dir}); code != 0 {
		t.Fatalf("republish exit %d", code)
	}
	site, err = db.Site(context.Background(), items[0].ID)
	if err != nil || site.Visibility != domain.VisOwner {
		t.Fatalf("republish without --visibility: %+v %v", site, err)
	}
}
