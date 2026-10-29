package sites

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/noomz/artifact-host/internal/blob"
	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/meta"
)

func setup(t *testing.T) (*Host, domain.Principal) {
	t.Helper()
	db, err := meta.Open("file:" + t.Name() + "?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	user := domain.UserID("user1")
	if err := db.CreateUser(ctx, user, "ada", []byte("hash1")); err != nil {
		t.Fatal(err)
	}
	h := New(db, blob.NewMemory())
	return h, domain.Principal{User: user}
}

func html() []domain.File {
	return []domain.File{{Path: "index.html", Body: []byte("<h1>hi</h1>")}}
}

func TestPublishAndPublicRead(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	out, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisPublic, Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	r, ctype, err := h.Open(ctx, nil, out.Site, "")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, _ := io.ReadAll(r)
	if string(b) != "<h1>hi</h1>" {
		t.Fatalf("got %q", b)
	}
	if !strings.Contains(ctype, "text/html") {
		t.Fatalf("ctype %q", ctype)
	}
}

func TestOwnerPrivate(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	out, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisOwner, Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.Open(ctx, nil, out.Site, "index.html"); err != domain.ErrUnauthorized {
		t.Fatalf("anon: %v", err)
	}
	if _, _, err := h.Open(ctx, &domain.Principal{User: "other"}, out.Site, "index.html"); err != domain.ErrForbidden {
		t.Fatalf("other: %v", err)
	}
	r, _, err := h.Open(ctx, &actor, out.Site, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
}

func TestTeamRead(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	if err := h.Meta.CreateTeam(ctx, "team1", "core"); err != nil {
		t.Fatal(err)
	}
	if err := h.Meta.CreateUser(ctx, "mate", "bea", []byte("hash2")); err != nil {
		t.Fatal(err)
	}
	if err := h.Meta.AddMember(ctx, "team1", "mate"); err != nil {
		t.Fatal(err)
	}
	out, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisTeam, Team: "team1", Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.Open(ctx, &domain.Principal{User: "stranger"}, out.Site, "index.html"); err != domain.ErrForbidden {
		t.Fatalf("stranger: %v", err)
	}
	r, _, err := h.Open(ctx, &domain.Principal{User: "mate", Teams: []domain.TeamID{"team1"}}, out.Site, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
}

func TestRejectTraversalAndMissingIndex(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	_, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisPublic, Files: []domain.File{{Path: "../x.html", Body: []byte("x")}}})
	if err != domain.ErrInvalid {
		t.Fatalf("traversal: %v", err)
	}
	_, err = h.Publish(ctx, actor, PublishIn{Visibility: domain.VisPublic, Files: []domain.File{{Path: "only.js", Body: []byte("1")}}})
	if err != domain.ErrInvalid {
		t.Fatalf("no index: %v", err)
	}
}

func TestRepublishNewVersion(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	out, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisPublic, Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	out2, err := h.Publish(ctx, actor, PublishIn{
		Site:       out.Site,
		Visibility: domain.VisPublic,
		Files:      []domain.File{{Path: "index.html", Body: []byte("v2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out2.Version == out.Version {
		t.Fatal("expected new version")
	}
	r, _, err := h.Open(ctx, nil, out.Site, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "v2" {
		t.Fatalf("got %q", b)
	}
}

func TestStrangerCannotRepublish(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	out, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisPublic, Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.Publish(ctx, domain.Principal{User: "eve"}, PublishIn{Site: out.Site, Visibility: domain.VisPublic, Files: html()})
	if err != domain.ErrForbidden {
		t.Fatalf("got %v", err)
	}
}

