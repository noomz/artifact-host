package cli

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const accessUsage = "usage: ah access SITE_ID (URL and user token required)"

func cmdAccess(args []string) int {
	fs := flag.NewFlagSet("access", flag.ContinueOnError)
	base := fs.String("url", os.Getenv("ARTIFACT_HOST_URL"), "server URL")
	token := fs.String("token", os.Getenv("ARTIFACT_HOST_TOKEN"), "user token")
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if *base == "" || *token == "" || len(positional) != 1 {
		fmt.Fprintln(os.Stderr, accessUsage)
		return 2
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(*base, "/")+"/v1/sites/"+url.PathEscape(positional[0])+"/access", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	return dump(req)
}
