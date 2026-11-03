package sites

import (
	"context"
	"errors"

	"github.com/noomz/artifact-host/internal/domain"
)

// Access is a site's grant state. It holds no secret, so it is safe to show.
type Access struct {
	HasPassword bool
	Links       []domain.SiteLink
}

// Grants reads grant state with no actor check. The caller must authorize.
func (h *Host) Grants(ctx context.Context, id domain.SiteID) (Access, error) {
	_, err := h.Meta.SitePassword(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return Access{}, err
	}
	hasPassword := err == nil
	links, err := h.Meta.SiteLinks(ctx, id)
	if err != nil {
		return Access{}, err
	}
	return Access{HasPassword: hasPassword, Links: links}, nil
}

// Access returns grant state to the site's owner only.
func (h *Host) Access(ctx context.Context, actor domain.Principal, id domain.SiteID) (Access, error) {
	s, err := h.ownedSite(ctx, actor, id)
	if err != nil {
		return Access{}, err
	}
	return h.Grants(ctx, s.ID)
}
