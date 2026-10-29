package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/noomz/artifact-host/internal/blob"
	"github.com/noomz/artifact-host/internal/httpapi"
	"github.com/noomz/artifact-host/internal/meta"
	"github.com/noomz/artifact-host/internal/sites"
)

func Main(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: ah serve|publish|user|team")
		return 2
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "publish":
		return cmdPublish(args[1:])
	case "user":
		return cmdUser(args[1:])
	case "team":
		return cmdTeam(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %s\n", args[0])
		return 2
	}
}

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", env("ARTIFACT_HOST_LISTEN", ":8080"), "listen address")
	sqlite := fs.String("sqlite", env("ARTIFACT_HOST_SQLITE", "artifact-host.db"), "sqlite path")
	base := fs.String("base-url", env("ARTIFACT_HOST_BASE_URL", "http://localhost:8080"), "public base URL")
	bucket := fs.String("s3-bucket", os.Getenv("ARTIFACT_HOST_S3_BUCKET"), "S3 bucket")
	endpoint := fs.String("s3-endpoint", os.Getenv("ARTIFACT_HOST_S3_ENDPOINT"), "S3 endpoint (minio)")
	region := fs.String("s3-region", env("ARTIFACT_HOST_S3_REGION", "us-east-1"), "S3 region")
	prefix := fs.String("s3-prefix", os.Getenv("ARTIFACT_HOST_S3_PREFIX"), "key prefix")
	pathStyle := fs.Bool("s3-path-style", os.Getenv("ARTIFACT_HOST_S3_PATH_STYLE") != "0", "path-style S3")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	admin := os.Getenv("ARTIFACT_HOST_ADMIN_TOKEN")
	if admin == "" {
		fmt.Fprintln(os.Stderr, "ARTIFACT_HOST_ADMIN_TOKEN is required")
		return 2
	}
	if *bucket == "" {
		fmt.Fprintln(os.Stderr, "--s3-bucket or ARTIFACT_HOST_S3_BUCKET is required")
		return 2
	}
	db, err := meta.Open(*sqlite)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer db.Close()
	s3, err := blob.NewS3(context.Background(), blob.S3Opts{
		Bucket:    *bucket,
		Prefix:    *prefix,
		Endpoint:  *endpoint,
		Region:    *region,
		PathStyle: *pathStyle,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	h := sites.New(db, s3)
	srv := httpapi.New(h, admin, *base)
	fmt.Fprintf(os.Stderr, "listening %s\n", *listen)
	if err := http.ListenAndServe(*listen, srv.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func cmdPublish(args []string) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory to publish")
	vis := fs.String("visibility", "public", "public|owner|team")
	team := fs.String("team", "", "team id when visibility=team")
	site := fs.String("site", "", "existing site id to replace")
	url := fs.String("url", os.Getenv("ARTIFACT_HOST_URL"), "server URL")
	token := fs.String("token", os.Getenv("ARTIFACT_HOST_TOKEN"), "user token")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" && fs.NArg() >= 1 {
		*dir = fs.Arg(0)
	}
	if *dir == "" || *url == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "publish needs a directory, --url or ARTIFACT_HOST_URL, and --token or ARTIFACT_HOST_TOKEN")
		return 2
	}
	body, err := tarDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*url, "/")+"/v1/sites", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	req.Header.Set("Visibility", *vis)
	if *team != "" {
		req.Header.Set("Team-Id", *team)
	}
	if *site != "" {
		req.Header.Set("Site-Id", *site)
	}
	return dump(req)
}

func cmdUser(args []string) int {
	if len(args) < 1 || args[0] != "add" {
		fmt.Fprintln(os.Stderr, "usage: ah user add NAME")
		return 2
	}
	fs := flag.NewFlagSet("user add", flag.ContinueOnError)
	url := fs.String("url", os.Getenv("ARTIFACT_HOST_URL"), "server URL")
	admin := fs.String("admin-token", os.Getenv("ARTIFACT_HOST_ADMIN_TOKEN"), "admin token")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 || *url == "" || *admin == "" {
		fmt.Fprintln(os.Stderr, "user add needs NAME, ARTIFACT_HOST_URL, ARTIFACT_HOST_ADMIN_TOKEN")
		return 2
	}
	payload, _ := json.Marshal(map[string]string{"name": fs.Arg(0)})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*url, "/")+"/v1/users", bytes.NewReader(payload))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+*admin)
	req.Header.Set("Content-Type", "application/json")
	return dump(req)
}

func cmdTeam(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: ah team add NAME | ah team add-member TEAM_ID USER_ID")
		return 2
	}
	url := os.Getenv("ARTIFACT_HOST_URL")
	admin := os.Getenv("ARTIFACT_HOST_ADMIN_TOKEN")
	if url == "" || admin == "" {
		fmt.Fprintln(os.Stderr, "ARTIFACT_HOST_URL and ARTIFACT_HOST_ADMIN_TOKEN required")
		return 2
	}
	switch args[0] {
	case "add":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: ah team add NAME")
			return 2
		}
		payload, _ := json.Marshal(map[string]string{"name": args[1]})
		req, err := http.NewRequest(http.MethodPost, strings.TrimRight(url, "/")+"/v1/teams", bytes.NewReader(payload))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", "application/json")
		return dump(req)
	case "add-member":
		if len(args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: ah team add-member TEAM_ID USER_ID")
			return 2
		}
		payload, _ := json.Marshal(map[string]string{"user_id": args[2]})
		req, err := http.NewRequest(http.MethodPost, strings.TrimRight(url, "/")+"/v1/teams/"+args[1]+"/members", bytes.NewReader(payload))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", "application/json")
		return dump(req)
	default:
		fmt.Fprintln(os.Stderr, "usage: ah team add NAME | ah team add-member TEAM_ID USER_ID")
		return 2
	}
}

func dump(req *http.Request) int {
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "%s\n%s\n", res.Status, b)
		return 1
	}
	os.Stdout.Write(b)
	return 0
}

func tarDir(root string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		base := filepath.Base(rel)
		if strings.HasPrefix(base, ".") && rel != ".well-known" && !strings.HasPrefix(rel, ".well-known/") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Name: rel, Mode: 0644, Size: int64(len(b))}); err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
