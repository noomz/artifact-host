package meta

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/noomz/artifact-host/internal/domain"

	_ "modernc.org/sqlite"
)

type DB struct {
	sql *sql.DB
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		_ = db.Close()
		return nil, err
	}
	m := &DB{sql: db}
	if err := m.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return m, nil
}

func (m *DB) Close() error { return m.sql.Close() }

func (m *DB) migrate() error {
	_, err := m.sql.Exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS team_members (
  team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (team_id, user_id)
);
CREATE TABLE IF NOT EXISTS sites (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id),
  team_id TEXT REFERENCES teams(id),
  visibility TEXT NOT NULL,
  current_version TEXT
);
CREATE TABLE IF NOT EXISTS versions (
  id TEXT PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(id) ON DELETE CASCADE
);
`)
	return err
}

func (m *DB) CreateUser(ctx context.Context, id domain.UserID, name string, tokenHash []byte) error {
	_, err := m.sql.ExecContext(ctx, `INSERT INTO users (id, name, token_hash) VALUES (?, ?, ?)`, id, name, tokenHash)
	return err
}

func (m *DB) UserByTokenHash(ctx context.Context, tokenHash []byte) (domain.User, error) {
	var u domain.User
	err := m.sql.QueryRowContext(ctx, `SELECT id, name FROM users WHERE token_hash = ?`, tokenHash).Scan(&u.ID, &u.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, domain.ErrUnauthorized
	}
	return u, err
}

func (m *DB) User(ctx context.Context, id domain.UserID) (domain.User, error) {
	var u domain.User
	err := m.sql.QueryRowContext(ctx, `SELECT id, name FROM users WHERE id = ?`, id).Scan(&u.ID, &u.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, domain.ErrNotFound
	}
	return u, err
}

func (m *DB) CreateTeam(ctx context.Context, id domain.TeamID, name string) error {
	_, err := m.sql.ExecContext(ctx, `INSERT INTO teams (id, name) VALUES (?, ?)`, id, name)
	return err
}

func (m *DB) AddMember(ctx context.Context, team domain.TeamID, user domain.UserID) error {
	_, err := m.sql.ExecContext(ctx, `INSERT OR IGNORE INTO team_members (team_id, user_id) VALUES (?, ?)`, team, user)
	return err
}

func (m *DB) TeamsForUser(ctx context.Context, user domain.UserID) ([]domain.TeamID, error) {
	rows, err := m.sql.QueryContext(ctx, `SELECT team_id FROM team_members WHERE user_id = ?`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.TeamID
	for rows.Next() {
		var id domain.TeamID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (m *DB) InsertSite(ctx context.Context, s domain.Site) error {
	var team any
	if s.Team != "" {
		team = string(s.Team)
	}
	_, err := m.sql.ExecContext(ctx, `INSERT INTO sites (id, owner_id, team_id, visibility, current_version) VALUES (?, ?, ?, ?, ?)`,
		s.ID, s.Owner, team, s.Visibility, nullVersion(s.Current))
	return err
}

func (m *DB) Site(ctx context.Context, id domain.SiteID) (domain.Site, error) {
	var s domain.Site
	var team sql.NullString
	var cur sql.NullString
	err := m.sql.QueryRowContext(ctx, `SELECT id, owner_id, team_id, visibility, current_version FROM sites WHERE id = ?`, id).
		Scan(&s.ID, &s.Owner, &team, &s.Visibility, &cur)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Site{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Site{}, err
	}
	if team.Valid {
		s.Team = domain.TeamID(team.String)
	}
	if cur.Valid {
		s.Current = domain.VersionID(cur.String)
	}
	return s, nil
}

func (m *DB) InsertVersion(ctx context.Context, site domain.SiteID, ver domain.VersionID) error {
	_, err := m.sql.ExecContext(ctx, `INSERT INTO versions (id, site_id) VALUES (?, ?)`, ver, site)
	return err
}

func (m *DB) SetCurrent(ctx context.Context, site domain.SiteID, ver domain.VersionID, vis domain.Visibility, team domain.TeamID) error {
	var t any
	if team != "" {
		t = string(team)
	}
	res, err := m.sql.ExecContext(ctx, `UPDATE sites SET current_version = ?, visibility = ?, team_id = ? WHERE id = ?`, ver, vis, t, site)
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

func nullVersion(v domain.VersionID) any {
	if v == "" {
		return nil
	}
	return string(v)
}

func (m *DB) Ping(ctx context.Context) error {
	if err := m.sql.PingContext(ctx); err != nil {
		return fmt.Errorf("sqlite: %w", err)
	}
	return nil
}
