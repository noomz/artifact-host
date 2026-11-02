package meta

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/noomz/artifact-host/internal/domain"
)

const (
	siteA = domain.SiteID("site-a")
	siteB = domain.SiteID("site-b")
	argon = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
)

var (
	now    = time.Unix(1_800_000_000, 0).UTC()
	future = now.Add(time.Hour)
)

func hash(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func openGrants(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "grants.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := db.CreateUser(ctx, "u", "Ada", []byte("token-hash")); err != nil {
		t.Fatal(err)
	}
	for _, id := range []domain.SiteID{siteA, siteB} {
		if err := db.InsertSite(ctx, domain.Site{ID: id, Owner: "u", Visibility: domain.VisOwner}); err != nil {
			t.Fatal(err)
		}
	}
	return db, path
}

func setPassword(t *testing.T, db *DB, site domain.SiteID, id domain.PasswordID) {
	t.Helper()
	if err := db.SetSitePassword(context.Background(), domain.SitePassword{ID: id, Site: site, Hash: argon}); err != nil {
		t.Fatal(err)
	}
}

func addLink(t *testing.T, db *DB, site domain.SiteID, id domain.LinkID, token byte, expires time.Time) {
	t.Helper()
	l := domain.SiteLink{ID: id, Site: site, Label: "l", CreatedAt: now, ExpiresAt: expires}
	if err := db.CreateSiteLink(context.Background(), l, hash(token)); err != nil {
		t.Fatal(err)
	}
}

func addSession(t *testing.T, db *DB, s domain.GrantSession, id byte) {
	t.Helper()
	if s.ExpiresAt.IsZero() {
		s.ExpiresAt = future
	}
	if err := db.CreateGrantSession(context.Background(), s, hash(id), now); err != nil {
		t.Fatal(err)
	}
}

func sessionLive(t *testing.T, db *DB, site domain.SiteID, id byte) bool {
	t.Helper()
	_, err := db.GrantSession(context.Background(), site, hash(id), now)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
	return err == nil
}

func TestSchemaRejectsNonHashSecrets(t *testing.T) {
	db, _ := openGrants(t)
	ctx := context.Background()
	if err := db.SetSitePassword(ctx, domain.SitePassword{ID: "p", Site: siteA, Hash: "hunter2hunter2"}); err == nil {
		t.Fatal("plaintext password stored")
	}
	if err := db.SetSitePassword(ctx, domain.SitePassword{ID: "p", Site: siteA, Hash: "$2a$10$bcryptbcrypt"}); err == nil {
		t.Fatal("non-argon2id hash stored")
	}
	l := domain.SiteLink{ID: "l", Site: siteA, CreatedAt: now, ExpiresAt: future}
	if err := db.CreateSiteLink(ctx, l, []byte("raw-token")); err == nil {
		t.Fatal("raw link token stored")
	}
	addLink(t, db, siteA, "l", 1, future)
	if err := db.CreateGrantSession(ctx, domain.GrantSession{Site: siteA, Link: "l", ExpiresAt: future}, []byte("raw-cookie"), now); err == nil {
		t.Fatal("raw session id stored")
	}
}

func TestFailedPasswordChangeKeepsOldPassword(t *testing.T) {
	db, _ := openGrants(t)
	ctx := context.Background()
	setPassword(t, db, siteA, "p1")
	addSession(t, db, domain.GrantSession{Site: siteA, Password: "p1"}, 1)
	if err := db.SetSitePassword(ctx, domain.SitePassword{ID: "p2", Site: siteA, Hash: "plaintext"}); err == nil {
		t.Fatal("bad hash accepted")
	}
	p, err := db.SitePassword(ctx, siteA)
	if err != nil || p.ID != "p1" || p.Hash != argon {
		t.Fatalf("password after failed change: %+v %v", p, err)
	}
	if !sessionLive(t, db, siteA, 1) {
		t.Fatal("failed change ended session")
	}
}

func TestPasswordChangeEndsOnlyPasswordSessions(t *testing.T) {
	db, _ := openGrants(t)
	ctx := context.Background()
	setPassword(t, db, siteA, "p1")
	addLink(t, db, siteA, "l", 1, future)
	addSession(t, db, domain.GrantSession{Site: siteA, Password: "p1"}, 1)
	addSession(t, db, domain.GrantSession{Site: siteA, Link: "l"}, 2)

	setPassword(t, db, siteA, "p2")
	if sessionLive(t, db, siteA, 1) {
		t.Fatal("password session survived change")
	}
	if !sessionLive(t, db, siteA, 2) {
		t.Fatal("link session ended by password change")
	}
	p, err := db.SitePassword(ctx, siteA)
	if err != nil || p.ID != "p2" {
		t.Fatalf("password: %+v %v", p, err)
	}

	addSession(t, db, domain.GrantSession{Site: siteA, Password: "p2"}, 3)
	if err := db.ClearSitePassword(ctx, siteA); err != nil {
		t.Fatal(err)
	}
	if sessionLive(t, db, siteA, 3) {
		t.Fatal("password session survived clear")
	}
	if !sessionLive(t, db, siteA, 2) {
		t.Fatal("link session ended by password clear")
	}
	if _, err := db.SitePassword(ctx, siteA); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cleared password: %v", err)
	}
	if err := db.ClearSitePassword(ctx, siteA); err != nil {
		t.Fatalf("second clear: %v", err)
	}
}

func TestRevokeEndsOnlyThatLink(t *testing.T) {
	db, _ := openGrants(t)
	ctx := context.Background()
	setPassword(t, db, siteA, "p")
	addLink(t, db, siteA, "l1", 1, future)
	addLink(t, db, siteA, "l2", 2, future)
	addSession(t, db, domain.GrantSession{Site: siteA, Password: "p"}, 1)
	addSession(t, db, domain.GrantSession{Site: siteA, Link: "l1"}, 2)
	addSession(t, db, domain.GrantSession{Site: siteA, Link: "l2"}, 3)

	if err := db.RevokeSiteLink(ctx, siteB, "l1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoke through another site: %v", err)
	}
	if !sessionLive(t, db, siteA, 2) {
		t.Fatal("revoke through another site took effect")
	}
	if err := db.RevokeSiteLink(ctx, siteA, "l1"); err != nil {
		t.Fatal(err)
	}
	if sessionLive(t, db, siteA, 2) {
		t.Fatal("revoked link session survived")
	}
	if !sessionLive(t, db, siteA, 1) || !sessionLive(t, db, siteA, 3) {
		t.Fatal("revoke ended another grant's session")
	}
	if _, err := db.SiteLinkByTokenHash(ctx, siteA, hash(1), now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoked token: %v", err)
	}
	if _, err := db.SiteLinkByTokenHash(ctx, siteA, hash(2), now); err != nil {
		t.Fatalf("other token: %v", err)
	}
	if err := db.RevokeSiteLink(ctx, siteA, "l1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	links, err := db.SiteLinks(ctx, siteA)
	if err != nil || len(links) != 1 || links[0].ID != "l2" || links[0].Label != "l" || !links[0].ExpiresAt.Equal(future) {
		t.Fatalf("links: %+v %v", links, err)
	}
}

func TestExpiryBoundary(t *testing.T) {
	db, _ := openGrants(t)
	ctx := context.Background()
	addLink(t, db, siteA, "l", 1, future)
	addSession(t, db, domain.GrantSession{Site: siteA, Link: "l", ExpiresAt: future}, 1)
	before, at := future.Add(-time.Second), future

	if _, err := db.SiteLinkByTokenHash(ctx, siteA, hash(1), before); err != nil {
		t.Fatalf("link before expiry: %v", err)
	}
	if _, err := db.SiteLinkByTokenHash(ctx, siteA, hash(1), at); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("link at expiry: %v", err)
	}
	s, err := db.GrantSession(ctx, siteA, hash(1), before)
	if err != nil || s.Link != "l" || s.Password != "" || s.Site != siteA || !s.ExpiresAt.Equal(future) {
		t.Fatalf("session before expiry: %+v %v", s, err)
	}
	if _, err := db.GrantSession(ctx, siteA, hash(1), at); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("session at expiry: %v", err)
	}
}

func TestGrantsAndSessionsSurviveRestart(t *testing.T) {
	db, path := openGrants(t)
	setPassword(t, db, siteA, "p")
	addLink(t, db, siteA, "l", 1, future)
	addSession(t, db, domain.GrantSession{Site: siteA, Password: "p"}, 1)
	addSession(t, db, domain.GrantSession{Site: siteA, Link: "l"}, 2)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	re, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer re.Close()
	if !sessionLive(t, re, siteA, 1) || !sessionLive(t, re, siteA, 2) {
		t.Fatal("session lost on restart")
	}
	if _, err := re.SitePassword(context.Background(), siteA); err != nil {
		t.Fatalf("password lost: %v", err)
	}
	if _, err := re.SiteLinkByTokenHash(context.Background(), siteA, hash(1), now); err != nil {
		t.Fatalf("link lost: %v", err)
	}
}

func TestGrantsStayOnOneSite(t *testing.T) {
	db, _ := openGrants(t)
	ctx := context.Background()
	setPassword(t, db, siteA, "p")
	addLink(t, db, siteA, "l", 1, future)
	addSession(t, db, domain.GrantSession{Site: siteA, Link: "l"}, 1)

	if sessionLive(t, db, siteB, 1) {
		t.Fatal("session granted another site")
	}
	if _, err := db.SiteLinkByTokenHash(ctx, siteB, hash(1), now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("token on another site: %v", err)
	}
	for name, s := range map[string]domain.GrantSession{
		"link":     {Site: siteB, Link: "l", ExpiresAt: future},
		"password": {Site: siteB, Password: "p", ExpiresAt: future},
	} {
		if err := db.CreateGrantSession(ctx, s, hash(2), now); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("session on another site's %s: %v", name, err)
		}
	}
}

func TestSessionNeedsExactlyOneLiveGrant(t *testing.T) {
	db, _ := openGrants(t)
	ctx := context.Background()
	setPassword(t, db, siteA, "p")
	addLink(t, db, siteA, "l", 1, future)
	if err := db.CreateGrantSession(ctx, domain.GrantSession{Site: siteA, ExpiresAt: future}, hash(1), now); err == nil {
		t.Fatal("session with no grant stored")
	}
	if err := db.CreateGrantSession(ctx, domain.GrantSession{Site: siteA, Password: "p", Link: "l", ExpiresAt: future}, hash(1), now); err == nil {
		t.Fatal("session with two grants stored")
	}
	if err := db.RevokeSiteLink(ctx, siteA, "l"); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateGrantSession(ctx, domain.GrantSession{Site: siteA, Link: "l", ExpiresAt: future}, hash(1), now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("session on revoked link: %v", err)
	}
	setPassword(t, db, siteA, "p2")
	if err := db.CreateGrantSession(ctx, domain.GrantSession{Site: siteA, Password: "p", ExpiresAt: future}, hash(1), now); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("session on replaced password: %v", err)
	}
}

func TestHasActiveGrant(t *testing.T) {
	db, _ := openGrants(t)
	ctx := context.Background()
	active := func() bool {
		t.Helper()
		ok, err := db.HasActiveGrant(ctx, siteA, now)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if active() {
		t.Fatal("no grants")
	}
	addLink(t, db, siteA, "old", 1, now)
	if active() {
		t.Fatal("expired link only")
	}
	addLink(t, db, siteA, "live", 2, future)
	if !active() {
		t.Fatal("live link")
	}
	if err := db.RevokeSiteLink(ctx, siteA, "live"); err != nil {
		t.Fatal(err)
	}
	setPassword(t, db, siteA, "p")
	if !active() {
		t.Fatal("password")
	}
	if ok, err := db.HasActiveGrant(ctx, siteB, now); err != nil || ok {
		t.Fatalf("other site: %v %v", ok, err)
	}
}

func TestCreateSessionPrunesExpired(t *testing.T) {
	db, _ := openGrants(t)
	setPassword(t, db, siteA, "p")
	addSession(t, db, domain.GrantSession{Site: siteA, Password: "p", ExpiresAt: now}, 1)
	addSession(t, db, domain.GrantSession{Site: siteA, Password: "p"}, 2)
	addSession(t, db, domain.GrantSession{Site: siteA, Password: "p"}, 3)
	var n int
	if err := db.sql.QueryRow(`SELECT count(*) FROM grant_sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("sessions = %d, want 2", n)
	}
}

func TestSiteDeleteCascadesGrants(t *testing.T) {
	db, _ := openGrants(t)
	ctx := context.Background()
	setPassword(t, db, siteA, "p")
	addLink(t, db, siteA, "l", 1, future)
	addSession(t, db, domain.GrantSession{Site: siteA, Password: "p"}, 1)
	addSession(t, db, domain.GrantSession{Site: siteA, Link: "l"}, 2)
	setPassword(t, db, siteB, "pb")
	addSession(t, db, domain.GrantSession{Site: siteB, Password: "pb"}, 3)

	if err := db.DeleteSite(ctx, siteA); err != nil {
		t.Fatal(err)
	}
	if links, err := db.SiteLinks(ctx, siteA); err != nil || len(links) != 0 {
		t.Fatalf("links survived site delete: %+v %v", links, err)
	}
	if sessionLive(t, db, siteA, 1) || sessionLive(t, db, siteA, 2) {
		t.Fatal("session survived site delete")
	}
	if _, err := db.SitePassword(ctx, siteA); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("password survived site delete: %v", err)
	}
	if !sessionLive(t, db, siteB, 3) {
		t.Fatal("other site's session ended")
	}
}

// V14: the store refuses these itself, so concurrent callers cannot get past a
// check made earlier in the request.
func TestPublicVisibilityAndGrantsExcludeEachOther(t *testing.T) {
	db, _ := openGrants(t)
	ctx := context.Background()
	versions := 0
	publish := func(site domain.SiteID, vis domain.Visibility) error {
		versions++
		ver := domain.VersionID(fmt.Sprintf("v%d", versions))
		if err := db.InsertVersion(ctx, site, ver); err != nil {
			t.Fatal(err)
		}
		return db.SetCurrent(ctx, site, ver, vis, "", nil, now)
	}

	setPassword(t, db, siteA, "p")
	if err := publish(siteA, domain.VisPublic); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("public with password: %v", err)
	}
	if s, err := db.Site(ctx, siteA); err != nil || s.Visibility != domain.VisOwner || s.Current != "" {
		t.Fatalf("refused update changed site: %+v %v", s, err)
	}
	if err := db.ClearSitePassword(ctx, siteA); err != nil {
		t.Fatal(err)
	}

	addLink(t, db, siteA, "live", 1, future)
	if err := publish(siteA, domain.VisPublic); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("public with live link: %v", err)
	}
	if err := publish(siteA, domain.VisOwner); err != nil {
		t.Fatalf("private republish with link: %v", err)
	}
	if err := db.RevokeSiteLink(ctx, siteA, "live"); err != nil {
		t.Fatal(err)
	}

	addLink(t, db, siteA, "old", 2, now.Add(-time.Hour))
	if err := publish(siteA, domain.VisPublic); err != nil {
		t.Fatalf("public with only an expired link: %v", err)
	}
	err := db.SetSitePassword(ctx, domain.SitePassword{ID: "q", Site: siteA, Hash: argon})
	if !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("password on public site: %v", err)
	}
	if _, err := db.SitePassword(ctx, siteA); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("password stored on public site: %v", err)
	}

	err = db.SetSitePassword(ctx, domain.SitePassword{ID: "r", Site: "missing", Hash: argon})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("password on missing site: %v", err)
	}
	err = db.SetCurrent(ctx, "missing", "v", domain.VisPublic, "", nil, now)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SetCurrent on missing site: %v", err)
	}
}

// V14
func TestCreateSiteLinkRefusesPublicAndMissingSite(t *testing.T) {
	db, _ := openGrants(t)
	ctx := context.Background()
	if err := db.InsertSite(ctx, domain.Site{ID: "pub", Owner: "u", Visibility: domain.VisPublic}); err != nil {
		t.Fatal(err)
	}
	l := domain.SiteLink{ID: "l", Site: "pub", CreatedAt: now, ExpiresAt: future}
	if err := db.CreateSiteLink(ctx, l, hash(1)); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("public site: %v", err)
	}
	l.Site = "missing"
	if err := db.CreateSiteLink(ctx, l, hash(1)); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing site: %v", err)
	}
	if links, err := db.SiteLinks(ctx, "pub"); err != nil || len(links) != 0 {
		t.Fatalf("links stored: %+v %v", links, err)
	}
}
