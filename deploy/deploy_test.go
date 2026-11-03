// Package deploy holds production config. These tests check the parts of it
// that the app's guarantees depend on.
package deploy

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// block returns the body of the first `{ ... }` block whose header starts with
// prefix. Config here has no braces inside strings, so counting is enough.
func block(t *testing.T, conf, prefix string) string {
	t.Helper()
	i := strings.Index(conf, prefix)
	if i < 0 {
		t.Fatalf("no block %q", prefix)
	}
	open := strings.Index(conf[i:], "{")
	if open < 0 {
		t.Fatalf("block %q has no body", prefix)
	}
	start := i + open + 1
	depth := 1
	for j := start; j < len(conf); j++ {
		switch conf[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return conf[start:j]
			}
		}
	}
	t.Fatalf("block %q not closed", prefix)
	return ""
}

func servers(t *testing.T, conf string) []string {
	t.Helper()
	var out []string
	for rest := conf; ; {
		i := strings.Index(rest, "server {")
		if i < 0 {
			return out
		}
		body := block(t, rest[i:], "server {")
		out = append(out, body)
		rest = rest[i+len("server {")+len(body):]
	}
}

func hasDirective(body, directive string) bool {
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(directive) + `\s*;`)
	return re.MatchString(body)
}

// V10: nginx does not log share-link paths.
func TestContentConfDoesNotLogLinkPaths(t *testing.T) {
	conf := read(t, "nginx-content.conf")
	srv := servers(t, conf)
	if len(srv) != 2 {
		t.Fatalf("want 2 server blocks, got %d", len(srv))
	}
	var tls, plain string
	for _, s := range srv {
		if strings.Contains(s, "listen 443 ssl") {
			tls = s
		} else {
			plain = s
		}
	}
	if tls == "" || plain == "" {
		t.Fatal("want one TLS and one plain HTTP server block")
	}
	if !hasDirective(plain, "access_log off") {
		t.Error("plain HTTP server must not log: its redirect sees link tokens too")
	}
	link := block(t, tls, "location ^~ /__ah/link/")
	if !hasDirective(link, "access_log off") {
		t.Error("/__ah/link/ location must set access_log off")
	}
	if !hasDirective(link, "error_log /dev/null") {
		t.Error("/__ah/link/ location must send error_log to /dev/null")
	}
	if !strings.Contains(link, "proxy_pass http://127.0.0.1:8088") {
		t.Error("/__ah/link/ location must proxy to the app")
	}
}

// Host routing (V5), Secure cookies (V7), and the per-IP limit (V9) read these.
func TestContentConfForwardsHeadersTheAppReads(t *testing.T) {
	tls := ""
	for _, s := range servers(t, read(t, "nginx-content.conf")) {
		if strings.Contains(s, "listen 443 ssl") {
			tls = s
		}
	}
	for _, d := range []string{
		"proxy_set_header Host $host",
		"proxy_set_header X-Forwarded-Proto $scheme",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for",
	} {
		if !hasDirective(tls, d) {
			t.Errorf("TLS server missing %q", d)
		}
	}
}

// I.deploy: compose, cert script, nginx, and install script name one domain.
func TestContentDomainMatchesAcrossDeployFiles(t *testing.T) {
	m := regexp.MustCompile(`(?m)^\s*ARTIFACT_HOST_CONTENT_DOMAIN:\s*(\S+)\s*$`).FindStringSubmatch(read(t, "docker-compose.yml"))
	if m == nil {
		t.Fatal("docker-compose.yml does not set ARTIFACT_HOST_CONTENT_DOMAIN")
	}
	d := m[1]
	if c := regexp.MustCompile(`(?m)^CONTENT_DOMAIN=(\S+)$`).FindStringSubmatch(read(t, "setup-wildcard-cert.sh")); c == nil || c[1] != d {
		t.Errorf("setup-wildcard-cert.sh CONTENT_DOMAIN %v, want %q", c, d)
	}
	conf := read(t, "nginx-content.conf")
	for _, want := range []string{
		"server_name *." + d + ";",
		"/etc/letsencrypt/live/" + d + "/fullchain.pem",
		"/etc/letsencrypt/live/" + d + "/privkey.pem",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("nginx-content.conf missing %q", want)
		}
	}
	install := read(t, "install-proxy-a.sh")
	for _, want := range []string{"/etc/letsencrypt/live/" + d + "/fullchain.pem", "nginx-content.conf", "." + d + "/"} {
		if !strings.Contains(install, want) {
			t.Errorf("install-proxy-a.sh missing %q", want)
		}
	}
}
