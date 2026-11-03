package cli

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/noomz/artifact-host/internal/httpapi"
)

func TestAccessPrintsGrantState(t *testing.T) {
	_, site := passwordFixture(t)

	if code := Main([]string{"link", "create", string(site), "--label", "for Ada"}); code != 0 {
		t.Fatalf("link create exit %d", code)
	}
	out, code := captureStdout(t, func() int { return Main([]string{"access", string(site)}) })
	if code != 0 {
		t.Fatalf("access exit %d", code)
	}
	var got struct {
		HasPassword bool `json:"has_password"`
		Links       []struct {
			Label string `json:"label"`
		} `json:"links"`
		ContentURL string `json:"content_url"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output %q: %v", out, err)
	}
	if got.HasPassword || len(got.Links) != 1 || got.Links[0].Label != "for Ada" {
		t.Fatalf("output %s", out)
	}
	if want := "https://" + string(site) + ".u.test/"; got.ContentURL != want {
		t.Fatalf("content_url %q, want %q", got.ContentURL, want)
	}
}

func TestAccessRefusals(t *testing.T) {
	host, site := passwordFixture(t)
	if err := host.Meta.CreateUser(context.Background(), "bob", "Bob", httpapi.TokenHash("bob-token")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		args  []string
		token string
		code  int
	}{
		{"no site", []string{"access"}, "token", 2},
		{"extra argument", []string{"access", string(site), "extra"}, "token", 2},
		{"no token", []string{"access", string(site)}, "", 2},
		{"not owner", []string{"access", string(site)}, "bob-token", 1},
		{"unknown site", []string{"access", "nope"}, "token", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("ARTIFACT_HOST_TOKEN", tc.token)
			if code := Main(tc.args); code != tc.code {
				t.Fatalf("exit %d, want %d", code, tc.code)
			}
		})
	}
}
