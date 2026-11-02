package sites

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

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

func TestPublishVisibilityDefaults(t *testing.T) {
	tests := []struct {
		name     string
		first    PublishIn
		second   PublishIn
		wantVis  domain.Visibility
		wantTeam domain.TeamID
	}{
		{"republish keeps owner", PublishIn{Visibility: domain.VisOwner}, PublishIn{}, domain.VisOwner, ""},
		{"republish keeps team", PublishIn{Visibility: domain.VisTeam, Team: "team1"}, PublishIn{}, domain.VisTeam, "team1"},
		{"republish keeps public", PublishIn{Visibility: domain.VisPublic}, PublishIn{}, domain.VisPublic, ""},
		{"explicit visibility replaces owner", PublishIn{Visibility: domain.VisOwner}, PublishIn{Visibility: domain.VisPublic}, domain.VisPublic, ""},
		{"explicit visibility replaces team", PublishIn{Visibility: domain.VisTeam, Team: "team1"}, PublishIn{Visibility: domain.VisOwner}, domain.VisOwner, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, actor := setup(t)
			ctx := context.Background()
			if err := h.Meta.CreateTeam(ctx, "team1", "core"); err != nil {
				t.Fatal(err)
			}
			tt.first.Files = html()
			out, err := h.Publish(ctx, actor, tt.first)
			if err != nil {
				t.Fatal(err)
			}
			tt.second.Site = out.Site
			tt.second.Files = html()
			if _, err := h.Publish(ctx, actor, tt.second); err != nil {
				t.Fatal(err)
			}
			got, err := h.Meta.Site(ctx, out.Site)
			if err != nil {
				t.Fatal(err)
			}
			if got.Visibility != tt.wantVis || got.Team != tt.wantTeam {
				t.Fatalf("got %q team %q, want %q team %q", got.Visibility, got.Team, tt.wantVis, tt.wantTeam)
			}
		})
	}
}

func TestNewSiteWithoutVisibilityIsPublic(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	out, err := h.Publish(ctx, actor, PublishIn{Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.Meta.Site(ctx, out.Site)
	if err != nil {
		t.Fatal(err)
	}
	if got.Visibility != domain.VisPublic {
		t.Fatalf("got %q", got.Visibility)
	}
}

func TestTeamWithoutVisibilityRejected(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	if _, err := h.Publish(ctx, actor, PublishIn{Team: "team1", Files: html()}); err != domain.ErrInvalid {
		t.Fatalf("new site: %v", err)
	}
	out, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisOwner, Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Publish(ctx, actor, PublishIn{Site: out.Site, Team: "team1", Files: html()}); err != domain.ErrInvalid {
		t.Fatalf("republish: %v", err)
	}
}

func TestDeleteSiteRemovesBlob(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	out, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisPublic, Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DeleteSite(ctx, out.Site); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.Open(ctx, nil, out.Site, "index.html"); err != domain.ErrNotFound {
		t.Fatalf("open after delete: %v", err)
	}
}

type failingDelete struct{ blob.Store }

func (failingDelete) DeletePrefix(context.Context, string) error {
	return errors.New("s3 down")
}

func TestDeleteSiteRemovesGrantsAfterBlob(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	now := time.Now()
	idHash := bytes.Repeat([]byte{1}, 32)
	out, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisOwner, Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Meta.SetSitePassword(ctx, domain.SitePassword{ID: "p", Site: out.Site, Hash: "$argon2id$x"}); err != nil {
		t.Fatal(err)
	}
	link := domain.SiteLink{ID: "l", Site: out.Site, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := h.Meta.CreateSiteLink(ctx, link, bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatal(err)
	}
	session := domain.GrantSession{Site: out.Site, Link: "l", ExpiresAt: now.Add(time.Hour)}
	if err := h.Meta.CreateGrantSession(ctx, session, idHash, now); err != nil {
		t.Fatal(err)
	}

	stored := h.Blob
	h.Blob = failingDelete{stored}
	if err := h.DeleteSite(ctx, out.Site); err == nil {
		t.Fatal("delete succeeded with blob failure")
	}
	if _, err := h.Meta.GrantSession(ctx, out.Site, idHash, now); err != nil {
		t.Fatalf("session after failed delete: %v", err)
	}
	if _, err := h.Meta.SitePassword(ctx, out.Site); err != nil {
		t.Fatalf("password after failed delete: %v", err)
	}

	h.Blob = stored
	if err := h.DeleteSite(ctx, out.Site); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Meta.GrantSession(ctx, out.Site, idHash, now); err != domain.ErrNotFound {
		t.Fatalf("session after delete: %v", err)
	}
	if _, err := h.Meta.SitePassword(ctx, out.Site); err != domain.ErrNotFound {
		t.Fatalf("password after delete: %v", err)
	}
	if links, err := h.Meta.SiteLinks(ctx, out.Site); err != nil || len(links) != 0 {
		t.Fatalf("links after delete: %+v %v", links, err)
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
