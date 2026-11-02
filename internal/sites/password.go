package sites

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/noomz/artifact-host/internal/domain"
)

const (
	PasswordMinBytes = 8
	PasswordMaxBytes = 1024

	argonMemoryKiB uint32 = 64 * 1024
	argonTime      uint32 = 3
	argonThreads   uint8  = 4
	argonSaltBytes        = 16
	argonKeyBytes  uint32 = 32

	// argonMaxMemoryKiB rejects a corrupt stored hash before it can allocate
	// without limit.
	argonMaxMemoryKiB uint32 = 1 << 20

	// noPasswordHash matches no password. Verifying against it costs the same as
	// a real hash, so timing does not reveal whether a site has a password.
	noPasswordHash = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

var (
	errBadPasswordLength = fmt.Errorf("%w: password must be %d to %d bytes", domain.ErrInvalid, PasswordMinBytes, PasswordMaxBytes)
	errGrantOnPublic     = fmt.Errorf("%w: public site cannot have a password or links", domain.ErrInvalid)
	errPublicWithGrants  = fmt.Errorf("%w: remove password and links before making site public", domain.ErrInvalid)
	errBadPasswordHash   = errors.New("stored password hash is malformed")

	// argonSlots caps concurrent hashes, because each one holds argonMemoryKiB and
	// anyone can trigger one through the login form.
	argonSlots = make(chan struct{}, 2)
)

func argonKey(ctx context.Context, password string, salt []byte, time, memoryKiB uint32, threads uint8, keyBytes uint32) ([]byte, error) {
	select {
	case argonSlots <- struct{}{}:
		defer func() { <-argonSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return argon2.IDKey([]byte(password), salt, time, memoryKiB, threads, keyBytes), nil
}

func hashPassword(ctx context.Context, password string) (string, error) {
	salt := make([]byte, argonSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := argonKey(ctx, password, salt, argonTime, argonMemoryKiB, argonThreads, argonKeyBytes)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemoryKiB, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func verifyPassword(ctx context.Context, encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return false, errBadPasswordHash
	}
	var memoryKiB, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memoryKiB, &time, &threads); err != nil {
		return false, errBadPasswordHash
	}
	// argon2.IDKey panics when time or threads is zero.
	if time == 0 || threads == 0 || memoryKiB > argonMaxMemoryKiB {
		return false, errBadPasswordHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errBadPasswordHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, errBadPasswordHash
	}
	got, err := argonKey(ctx, password, salt, time, memoryKiB, threads, uint32(len(want)))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// ownedSite loads a site for a grant change. Only the owner may change grants:
// not an admin, and not a team member.
func (h *Host) ownedSite(ctx context.Context, actor domain.Principal, id domain.SiteID) (domain.Site, error) {
	s, err := h.Meta.Site(ctx, id)
	if err != nil {
		return domain.Site{}, err
	}
	if actor.User == "" || actor.User != s.Owner {
		return domain.Site{}, domain.ErrForbidden
	}
	return s, nil
}

func (h *Host) SetPassword(ctx context.Context, actor domain.Principal, id domain.SiteID, password string) error {
	s, err := h.ownedSite(ctx, actor, id)
	if err != nil {
		return err
	}
	if len(password) < PasswordMinBytes || len(password) > PasswordMaxBytes {
		return errBadPasswordLength
	}
	if s.Visibility == domain.VisPublic {
		return errGrantOnPublic
	}
	hash, err := hashPassword(ctx, password)
	if err != nil {
		return err
	}
	return h.Meta.SetSitePassword(ctx, domain.SitePassword{ID: domain.PasswordID(NewID()), Site: s.ID, Hash: hash})
}

func (h *Host) ClearPassword(ctx context.Context, actor domain.Principal, id domain.SiteID) error {
	s, err := h.ownedSite(ctx, actor, id)
	if err != nil {
		return err
	}
	return h.Meta.ClearSitePassword(ctx, s.ID)
}

// VerifyPassword returns ErrUnauthorized for a wrong password and for a site with
// no password, at the same cost, so a viewer cannot tell the two apart.
func (h *Host) VerifyPassword(ctx context.Context, id domain.SiteID, password string) (domain.PasswordID, error) {
	p, err := h.Meta.SitePassword(ctx, id)
	if errors.Is(err, domain.ErrNotFound) {
		p = domain.SitePassword{Hash: noPasswordHash}
	} else if err != nil {
		return "", err
	}
	ok, err := verifyPassword(ctx, p.Hash, password)
	if err != nil {
		return "", err
	}
	if !ok || p.ID == "" {
		return "", domain.ErrUnauthorized
	}
	return p.ID, nil
}
