package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/sites"
)

func TestDiscoveryAndRename(t *testing.T) {
	s, ts, _ := testServer(t)
	ctx := context.Background()
	for _, u := range []string{"alice", "bob", "eve"} {
		if err := s.Host.Meta.CreateUser(ctx, domain.UserID(u), u, TokenHash(u)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Host.Meta.CreateTeam(ctx, "team", "team"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob"} {
		if err := s.Host.Meta.AddMember(ctx, "team", domain.UserID(u)); err != nil {
			t.Fatal(err)
		}
	}
	publish := func(user, vis, team, name string) string {
		t.Helper()
		req, _ := http.NewRequest("POST", ts.URL+"/v1/sites", tarBody(t, map[string]string{"index.html": "hello"}))
		req.Header.Set("Authorization", "Bearer "+user)
		req.Header.Set("Visibility", vis)
		req.Header.Set("Team-Id", team)
		req.Header.Set("Site-Name", url.QueryEscape(name))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != 201 {
			b, _ := io.ReadAll(res.Body)
			t.Fatalf("publish %d %s", res.StatusCode, b)
		}
		var out struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out.ID
	}
	owned := publish("alice", "owner", "", "  Café  ")
	shared := publish("bob", "team", "team", "Team Board")
	publish("bob", "owner", "", "Secret")
	publish("eve", "public", "", "Public")
	list := func(user, query string) []siteResult {
		t.Helper()
		req, _ := http.NewRequest("GET", ts.URL+"/v1/sites"+query, nil)
		if user != "" {
			req.Header.Set("Authorization", "Bearer "+user)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if user == "" {
			if res.StatusCode != 401 {
				t.Fatalf("anonymous list %d", res.StatusCode)
			}
			return nil
		}
		if res.StatusCode != 200 {
			t.Fatalf("list %d", res.StatusCode)
		}
		var out []siteResult
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	list("", "")
	got := list("alice", "")
	if len(got) != 2 {
		t.Fatalf("accessible = %+v", got)
	}
	got = list("alice", "?name=CAF%C3%89&scope=owned")
	if len(got) != 1 || string(got[0].ID) != owned || got[0].Name != "Café" {
		t.Fatalf("filtered = %+v", got)
	}
	got = list("alice", "?scope=team&visibility=team")
	if len(got) != 1 || string(got[0].ID) != shared {
		t.Fatalf("team = %+v", got)
	}
	rename := func(user, id, name string) int {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"name": name})
		req, _ := http.NewRequest("PATCH", ts.URL+"/v1/sites/"+id, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+user)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		return res.StatusCode
	}
	if status := rename("bob", owned, "stolen"); status != 403 {
		t.Fatalf("nonowner rename %d", status)
	}
	if status := rename("alice", owned, strings.Repeat("界", 201)); status != 400 {
		t.Fatalf("long name %d", status)
	}
	if status := rename("alice", owned, " 新しい "); status != 204 {
		t.Fatalf("rename %d", status)
	}
	before, err := s.Host.Meta.Site(ctx, domain.SiteID(owned))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Host.Publish(ctx, domain.Principal{User: "alice"}, sites.PublishIn{Site: before.ID, Visibility: domain.VisOwner, Files: []domain.File{{Path: "index.html", Body: []byte("updated")}}})
	if err != nil {
		t.Fatal(err)
	}
	after, err := s.Host.Meta.Site(ctx, before.ID)
	if err != nil || after.Name != "新しい" || after.Current == before.Current {
		t.Fatalf("republish %+v %v", after, err)
	}
	if status := rename("alice", owned, "  "); status != 204 {
		t.Fatalf("clear %d", status)
	}
	after, err = s.Host.Meta.Site(ctx, before.ID)
	if err != nil || after.Name != "" {
		t.Fatalf("clear %+v %v", after, err)
	}
}
