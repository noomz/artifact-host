package meta

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/noomz/artifact-host/internal/domain"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// SetSitePassword replaces the site's password. The new row has a new ID, so
// sessions from the old password cascade away, and a login still verifying the
// old password cannot create a session afterwards. It returns ErrInvalid on a
// public site. The DELETE takes the write lock first, so the visibility read
// cannot go stale before the INSERT.
func (m *DB) SetSitePassword(ctx context.Context, p domain.SitePassword) error {
	tx, err := m.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM site_passwords WHERE site_id = ?`, p.Site); err != nil {
		return err
	}
	var vis domain.Visibility
	err = tx.QueryRowContext(ctx, `SELECT visibility FROM sites WHERE id = ?`, p.Site).Scan(&vis)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}
	if vis == domain.VisPublic {
		return domain.ErrInvalid
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO site_passwords (id, site_id, hash) VALUES (?, ?, ?)`, p.ID, p.Site, p.Hash); err != nil {
		return staleGrant(err)
	}
	return tx.Commit()
}

func (m *DB) ClearSitePassword(ctx context.Context, site domain.SiteID) error {
	_, err := m.sql.ExecContext(ctx, `DELETE FROM site_passwords WHERE site_id = ?`, site)
	return err
}

func (m *DB) SitePassword(ctx context.Context, site domain.SiteID) (domain.SitePassword, error) {
	var p domain.SitePassword
	err := m.sql.QueryRowContext(ctx, `SELECT id, site_id, hash FROM site_passwords WHERE site_id = ?`, site).Scan(&p.ID, &p.Site, &p.Hash)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SitePassword{}, domain.ErrNotFound
	}
	return p, err
}

func (m *DB) CreateSiteLink(ctx context.Context, l domain.SiteLink, tokenHash []byte) error {
	_, err := m.sql.ExecContext(ctx, `INSERT INTO site_links (id, site_id, token_hash, label, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		l.ID, l.Site, tokenHash, l.Label, l.CreatedAt.Unix(), l.ExpiresAt.Unix())
	return staleGrant(err)
}

// SiteLinks lists all of a site's links, including expired ones.
func (m *DB) SiteLinks(ctx context.Context, site domain.SiteID) ([]domain.SiteLink, error) {
	rows, err := m.sql.QueryContext(ctx, `SELECT id, site_id, label, created_at, expires_at FROM site_links WHERE site_id = ? ORDER BY created_at, id`, site)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.SiteLink{}
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SiteLinkByTokenHash finds a live link. Unknown, expired, and another site's
// links all return ErrNotFound.
func (m *DB) SiteLinkByTokenHash(ctx context.Context, site domain.SiteID, tokenHash []byte, now time.Time) (domain.SiteLink, error) {
	row := m.sql.QueryRowContext(ctx, `SELECT id, site_id, label, created_at, expires_at FROM site_links WHERE site_id = ? AND token_hash = ? AND expires_at > ?`, site, tokenHash, now.Unix())
	l, err := scanLink(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.SiteLink{}, domain.ErrNotFound
	}
	return l, err
}

func (m *DB) RevokeSiteLink(ctx context.Context, site domain.SiteID, id domain.LinkID) error {
	res, err := m.sql.ExecContext(ctx, `DELETE FROM site_links WHERE site_id = ? AND id = ?`, site, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (m *DB) HasActiveGrant(ctx context.Context, site domain.SiteID, now time.Time) (bool, error) {
	var active bool
	err := m.sql.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM site_passwords WHERE site_id = ?) OR EXISTS (SELECT 1 FROM site_links WHERE site_id = ? AND expires_at > ?)`,
		site, site, now.Unix()).Scan(&active)
	return active, err
}

// CreateGrantSession stores a session and prunes expired ones. It returns
// ErrNotFound if the grant no longer exists or belongs to another site.
func (m *DB) CreateGrantSession(ctx context.Context, s domain.GrantSession, idHash []byte, now time.Time) error {
	tx, err := m.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM grant_sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO grant_sessions (id_hash, site_id, password_id, link_id, expires_at) VALUES (?, ?, ?, ?, ?)`,
		idHash, s.Site, nullIfEmpty(string(s.Password)), nullIfEmpty(string(s.Link)), s.ExpiresAt.Unix()); err != nil {
		return staleGrant(err)
	}
	return tx.Commit()
}

// GrantSession finds a live session for this site only, so a session from one
// site never grants another.
func (m *DB) GrantSession(ctx context.Context, site domain.SiteID, idHash []byte, now time.Time) (domain.GrantSession, error) {
	var s domain.GrantSession
	var password, link sql.NullString
	var expires int64
	err := m.sql.QueryRowContext(ctx, `SELECT site_id, password_id, link_id, expires_at FROM grant_sessions WHERE site_id = ? AND id_hash = ? AND expires_at > ?`, site, idHash, now.Unix()).
		Scan(&s.Site, &password, &link, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.GrantSession{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.GrantSession{}, err
	}
	s.Password = domain.PasswordID(password.String)
	s.Link = domain.LinkID(link.String)
	s.ExpiresAt = time.Unix(expires, 0).UTC()
	return s, nil
}

func scanLink(row interface{ Scan(...any) error }) (domain.SiteLink, error) {
	var l domain.SiteLink
	var created, expires int64
	if err := row.Scan(&l.ID, &l.Site, &l.Label, &created, &expires); err != nil {
		return domain.SiteLink{}, err
	}
	l.CreatedAt = time.Unix(created, 0).UTC()
	l.ExpiresAt = time.Unix(expires, 0).UTC()
	return l, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// staleGrant maps a foreign key failure to ErrNotFound: the site or grant was
// removed, or the session names another site's grant.
func staleGrant(err error) error {
	var e *sqlite.Error
	if errors.As(err, &e) && e.Code() == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY {
		return domain.ErrNotFound
	}
	return err
}
