package sites

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/noomz/artifact-host/internal/domain"
)

func TestHashAndVerifyPassword(t *testing.T) {
	ctx := context.Background()
	a, err := hashPassword(ctx, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	b, err := hashPassword(ctx, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("same salt used twice")
	}
	if ok, err := verifyPassword(ctx, a, "correct horse"); err != nil || !ok {
		t.Fatalf("right password: %v %v", ok, err)
	}
	if ok, err := verifyPassword(ctx, a, "wrong horse"); err != nil || ok {
		t.Fatalf("wrong password: %v %v", ok, err)
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	const salt = "c2FsdHNhbHQ"
	const key = "aGFzaGhhc2g"
	for _, bad := range []string{
		"",
		"plain",
		"$argon2i$v=19$m=65536,t=3,p=4$" + salt + "$" + key,
		"$argon2id$v=18$m=65536,t=3,p=4$" + salt + "$" + key,
		"$argon2id$v=19$m=65536,t=0,p=4$" + salt + "$" + key,
		"$argon2id$v=19$m=65536,t=3,p=0$" + salt + "$" + key,
		"$argon2id$v=19$m=65536,t=3,p=999$" + salt + "$" + key,
		"$argon2id$v=19$m=99999999,t=3,p=4$" + salt + "$" + key,
		"$argon2id$v=19$m=65536,t=3,p=4$!!$" + key,
		"$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$!!",
		"$argon2id$v=19$m=65536,t=3,p=4$" + salt + "$",
	} {
		if ok, err := verifyPassword(context.Background(), bad, "x"); ok || !errors.Is(err, errBadPasswordHash) {
			t.Errorf("verifyPassword(%q) = %v, %v", bad, ok, err)
		}
	}
}

func TestNoPasswordHashIsWellFormedAndSameCost(t *testing.T) {
	ok, err := verifyPassword(context.Background(), noPasswordHash, "anything")
	if err != nil || ok {
		t.Fatalf("%v %v", ok, err)
	}
	real, err := hashPassword(context.Background(), "anything")
	if err != nil {
		t.Fatal(err)
	}
	prefix := func(h string) string { return h[:strings.LastIndex(h[:strings.LastIndex(h, "$")], "$")] }
	if prefix(real) != prefix(noPasswordHash) {
		t.Fatalf("parameters differ: %s vs %s", prefix(real), prefix(noPasswordHash))
	}
	if len(real) != len(noPasswordHash) {
		t.Fatalf("salt or key length differs: %d vs %d", len(real), len(noPasswordHash))
	}
}

func TestVerifyPasswordStopsWhenContextEnds(t *testing.T) {
	for range cap(argonSlots) {
		argonSlots <- struct{}{}
	}
	defer func() {
		for range cap(argonSlots) {
			<-argonSlots
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hashPassword(ctx, "password"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}

func TestVerifySitePassword(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	out, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisOwner, Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.VerifyPassword(ctx, out.Site, "any password"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("no password set: %v", err)
	}
	if err := h.SetPassword(ctx, actor, out.Site, "the password"); err != nil {
		t.Fatal(err)
	}
	stored, err := h.Meta.SitePassword(ctx, out.Site)
	if err != nil {
		t.Fatal(err)
	}
	id, err := h.VerifyPassword(ctx, out.Site, "the password")
	if err != nil || id != stored.ID {
		t.Fatalf("right password: %q %v", id, err)
	}
	if _, err := h.VerifyPassword(ctx, out.Site, "not the password"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("wrong password: %v", err)
	}
}

// V14
func TestPublishPublicRefusedWhileGrantsExist(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	out, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisOwner, Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SetPassword(ctx, actor, out.Site, "the password"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Publish(ctx, actor, PublishIn{Site: out.Site, Visibility: domain.VisPublic, Files: html()}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("password: %v", err)
	}
	// A refused publish changes nothing and stores no new version.
	s, err := h.Meta.Site(ctx, out.Site)
	if err != nil || s.Visibility != domain.VisOwner || s.Current != out.Version {
		t.Fatalf("site %+v %v", s, err)
	}
	if err := h.ClearPassword(ctx, actor, out.Site); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	live := domain.SiteLink{ID: "live", Site: out.Site, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := h.Meta.CreateSiteLink(ctx, live, bytes32(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Publish(ctx, actor, PublishIn{Site: out.Site, Visibility: domain.VisPublic, Files: html()}); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("link: %v", err)
	}
	if err := h.Meta.RevokeSiteLink(ctx, out.Site, "live"); err != nil {
		t.Fatal(err)
	}

	expired := domain.SiteLink{ID: "old", Site: out.Site, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	if err := h.Meta.CreateSiteLink(ctx, expired, bytes32(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Publish(ctx, actor, PublishIn{Site: out.Site, Visibility: domain.VisPublic, Files: html()}); err != nil {
		t.Fatalf("expired link blocked publish: %v", err)
	}
	if err := h.SetPassword(ctx, actor, out.Site, "the password"); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("password on public site: %v", err)
	}
}

// V14: republish that does not ask for public keeps working with grants.
func TestRepublishKeepsGrants(t *testing.T) {
	h, actor := setup(t)
	ctx := context.Background()
	out, err := h.Publish(ctx, actor, PublishIn{Visibility: domain.VisOwner, Files: html()})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.SetPassword(ctx, actor, out.Site, "the password"); err != nil {
		t.Fatal(err)
	}
	stored, err := h.Meta.SitePassword(ctx, out.Site)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Publish(ctx, actor, PublishIn{Site: out.Site, Files: html()}); err != nil {
		t.Fatal(err)
	}
	after, err := h.Meta.SitePassword(ctx, out.Site)
	if err != nil || after.ID != stored.ID {
		t.Fatalf("password after republish: %+v %v", after, err)
	}
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
