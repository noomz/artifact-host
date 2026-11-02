package sites

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/noomz/artifact-host/internal/domain"
)

const (
	LinkDefaultTTL = 7 * 24 * time.Hour
	LinkMaxTTL     = 365 * 24 * time.Hour

	// linkMinTTL is above the one-second precision of stored expiry, so a new
	// link cannot be expired already.
	linkMinTTL = time.Minute

	linkTokenBytes = 32
)

var errBadLinkExpiry = fmt.Errorf("%w: expiry must be 1m to 365d, like 7d or 12h", domain.ErrInvalid)

// parseLinkTTL reads "7d" or a Go duration such as "12h". Empty means the default.
func parseLinkTTL(raw string) (time.Duration, error) {
	if raw == "" {
		return LinkDefaultTTL, nil
	}
	var ttl time.Duration
	if days, ok := strings.CutSuffix(raw, "d"); ok {
		// Checking the count first keeps the multiplication from overflowing.
		n, err := strconv.Atoi(days)
		if err != nil || n < 1 || n > 365 {
			return 0, errBadLinkExpiry
		}
		ttl = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if ttl, err = time.ParseDuration(raw); err != nil {
			return 0, errBadLinkExpiry
		}
	}
	if ttl < linkMinTTL || ttl > LinkMaxTTL {
		return 0, errBadLinkExpiry
	}
	return ttl, nil
}

func linkTokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// CreateLink returns the raw token. Only its hash is stored, so the caller's
// response is the one time anyone sees it.
func (h *Host) CreateLink(ctx context.Context, actor domain.Principal, id domain.SiteID, label, expiresIn string) (domain.SiteLink, string, error) {
	s, err := h.ownedSite(ctx, actor, id)
	if err != nil {
		return domain.SiteLink{}, "", err
	}
	label, err = domain.NormalizeName(label)
	if err != nil {
		return domain.SiteLink{}, "", err
	}
	ttl, err := parseLinkTTL(expiresIn)
	if err != nil {
		return domain.SiteLink{}, "", err
	}
	b := make([]byte, linkTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return domain.SiteLink{}, "", err
	}
	token := hex.EncodeToString(b)
	now := time.Now().UTC()
	link := domain.SiteLink{ID: domain.LinkID(NewID()), Site: s.ID, Label: label, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if err := h.Meta.CreateSiteLink(ctx, link, linkTokenHash(token)); err != nil {
		if errors.Is(err, domain.ErrInvalid) {
			return domain.SiteLink{}, "", errGrantOnPublic
		}
		return domain.SiteLink{}, "", err
	}
	return link, token, nil
}

func (h *Host) RevokeLink(ctx context.Context, actor domain.Principal, id domain.SiteID, link domain.LinkID) error {
	s, err := h.ownedSite(ctx, actor, id)
	if err != nil {
		return err
	}
	return h.Meta.RevokeSiteLink(ctx, s.ID, link)
}

// LinkByToken returns ErrNotFound for an unknown, expired, or revoked token, and
// for another site's token.
func (h *Host) LinkByToken(ctx context.Context, id domain.SiteID, token string) (domain.SiteLink, error) {
	return h.Meta.SiteLinkByTokenHash(ctx, id, linkTokenHash(token), time.Now())
}
