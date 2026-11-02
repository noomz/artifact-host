package meta

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/noomz/artifact-host/internal/domain"
)

func TestForeignKeysOnEveryConnection(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "fk.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.sql.SetConnMaxLifetime(time.Nanosecond)
	time.Sleep(time.Millisecond)
	var on int
	if err := db.sql.QueryRow(`PRAGMA foreign_keys`).Scan(&on); err != nil {
		t.Fatal(err)
	}
	if on != 1 {
		t.Fatalf("foreign_keys = %d on replacement connection", on)
	}
}

func TestLegacySitesGainNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash BLOB NOT NULL UNIQUE);
 CREATE TABLE teams (id TEXT PRIMARY KEY, name TEXT NOT NULL);
 CREATE TABLE sites (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL REFERENCES users(id), team_id TEXT REFERENCES teams(id), visibility TEXT NOT NULL, current_version TEXT);
 INSERT INTO users VALUES ('u','Ada',x'01'); INSERT INTO sites VALUES ('s','u',NULL,'public','v');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		db, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		site, err := db.Site(context.Background(), "s")
		if err != nil || site.Name != "" || site.Current != "v" {
			t.Fatalf("migrated: %+v %v", site, err)
		}
		if site.Owner != "u" || site.Visibility != domain.VisPublic {
			t.Fatalf("site changed: %+v", site)
		}
		if u, err := db.UserByTokenHash(context.Background(), []byte{1}); err != nil || u.ID != "u" {
			t.Fatalf("token lookup: %+v %v", u, err)
		}
		active, err := db.HasActiveGrant(context.Background(), "s", time.Now())
		if err != nil || active {
			t.Fatalf("legacy site grant: %v %v", active, err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
