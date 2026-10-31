package meta

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

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
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
