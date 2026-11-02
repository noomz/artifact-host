package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const linkUsage = "usage: ah link create SITE_ID [--label L] [--expires 7d] | ah link revoke SITE_ID LINK_ID (URL and user token required)"

func cmdLink(args []string) int {
	if len(args) < 1 || (args[0] != "create" && args[0] != "revoke") {
		fmt.Fprintln(os.Stderr, linkUsage)
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("link "+action, flag.ContinueOnError)
	base := fs.String("url", os.Getenv("ARTIFACT_HOST_URL"), "server URL")
	token := fs.String("token", os.Getenv("ARTIFACT_HOST_TOKEN"), "user token")
	var label, expires *string
	wantArgs := 2
	if action == "create" {
		label = fs.String("label", "", "label shown in access listings")
		expires = fs.String("expires", "", "time until expiry, like 7d or 12h (default 7d, maximum 365d)")
		wantArgs = 1
	}
	positional, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return 2
	}
	if *base == "" || *token == "" || len(positional) != wantArgs {
		fmt.Fprintln(os.Stderr, linkUsage)
		return 2
	}
	endpoint := strings.TrimRight(*base, "/") + "/v1/sites/" + url.PathEscape(positional[0]) + "/links"
	var req *http.Request
	if action == "revoke" {
		req, err = http.NewRequest(http.MethodDelete, endpoint+"/"+url.PathEscape(positional[1]), nil)
	} else {
		var body []byte
		if body, err = json.Marshal(map[string]string{"label": *label, "expires_in": *expires}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		req, err = http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	return dump(req)
}
