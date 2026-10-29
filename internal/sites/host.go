package sites

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"mime"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/noomz/artifact-host/internal/blob"
	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/meta"
)

type Host struct {
	Meta *meta.DB
	Blob blob.Store
}

func New(m *meta.DB, b blob.Store) *Host {
	return &Host{Meta: m, Blob: b}
}

type PublishIn struct {
	Site       domain.SiteID
	Visibility domain.Visibility
	Team       domain.TeamID
	Files      []domain.File
}

type PublishOut struct {
	Site    domain.SiteID
	Version domain.VersionID
}

func (h *Host) Publish(ctx context.Context, actor domain.Principal, in PublishIn) (PublishOut, error) {
	files, err := NormalizeFiles(in.Files)
	if err != nil {
		return PublishOut{}, err
	}
	if err := in.Visibility.Check(in.Team); err != nil {
		return PublishOut{}, err
	}

	var existing *domain.Site
	if in.Site != "" {
		s, err := h.Meta.Site(ctx, in.Site)
		if err != nil {
			return PublishOut{}, err
		}
		existing = &s
	}
	if !domain.CanWrite(actor, existing) {
		if actor.User == "" && !actor.Admin {
			return PublishOut{}, domain.ErrUnauthorized
		}
		return PublishOut{}, domain.ErrForbidden
	}

	siteID := in.Site
	owner := actor.User
	if existing != nil {
		siteID = existing.ID
		owner = existing.Owner
	} else {
		if owner == "" {
			return PublishOut{}, domain.ErrUnauthorized
		}
		siteID = domain.SiteID(NewID())
		if err := h.Meta.InsertSite(ctx, domain.Site{
			ID:         siteID,
			Owner:      owner,
			Team:       in.Team,
			Visibility: in.Visibility,
		}); err != nil {
			return PublishOut{}, err
		}
	}

	ver := domain.VersionID(NewID())
	if err := h.Meta.InsertVersion(ctx, siteID, ver); err != nil {
		return PublishOut{}, err
	}
	for _, f := range files {
		key := objectKey(siteID, ver, f.Path)
		if err := h.Blob.Put(ctx, key, f.Body, f.ContentType); err != nil {
			return PublishOut{}, err
		}
	}
	if err := h.Meta.SetCurrent(ctx, siteID, ver, in.Visibility, in.Team); err != nil {
		return PublishOut{}, err
	}
	return PublishOut{Site: siteID, Version: ver}, nil
}

func (h *Host) Open(ctx context.Context, actor *domain.Principal, siteID domain.SiteID, filePath string) (io.ReadCloser, string, error) {
	s, err := h.Meta.Site(ctx, siteID)
	if err != nil {
		return nil, "", err
	}
	if !domain.CanRead(actor, s) {
		if actor == nil {
			return nil, "", domain.ErrUnauthorized
		}
		return nil, "", domain.ErrForbidden
	}
	if s.Current == "" {
		return nil, "", domain.ErrNotFound
	}
	filePath, err = CleanPath(filePath)
	if err != nil {
		return nil, "", err
	}
	if filePath == "" || strings.HasSuffix(filePath, "/") {
		filePath = "index.html"
	}
	r, ctype, err := h.Blob.Get(ctx, objectKey(s.ID, s.Current, filePath))
	if err != nil {
		if err == blob.ErrNotFound {
			return nil, "", domain.ErrNotFound
		}
		return nil, "", err
	}
	if ctype == "" {
		ctype = typeFor(filePath)
	}
	return r, ctype, nil
}

func objectKey(site domain.SiteID, ver domain.VersionID, p string) string {
	return string(site) + "/" + string(ver) + "/" + p
}

func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func NormalizeFiles(files []domain.File) ([]domain.File, error) {
	if len(files) == 0 {
		return nil, domain.ErrInvalid
	}
	out := make([]domain.File, 0, len(files))
	seen := map[string]struct{}{}
	hasIndex := false
	for _, f := range files {
		p, err := CleanPath(f.Path)
		if err != nil {
			return nil, err
		}
		if p == "" {
			return nil, domain.ErrInvalid
		}
		if _, dup := seen[p]; dup {
			return nil, domain.ErrInvalid
		}
		seen[p] = struct{}{}
		if p == "index.html" {
			hasIndex = true
		}
		body := f.Body
		if !utf8.Valid(body) && strings.HasPrefix(typeFor(p), "text/") {
			return nil, domain.ErrInvalid
		}
		ctype := f.ContentType
		if ctype == "" {
			ctype = typeFor(p)
		}
		out = append(out, domain.File{Path: p, Body: body, ContentType: ctype})
	}
	if !hasIndex {
		return nil, domain.ErrInvalid
	}
	return out, nil
}

func CleanPath(p string) (string, error) {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "", nil
	}
	if strings.Contains(p, "\x00") {
		return "", domain.ErrInvalid
	}
	clean := path.Clean(p)
	if clean == "." {
		return "", nil
	}
	if clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
		return "", domain.ErrInvalid
	}
	for _, part := range strings.Split(clean, "/") {
		if part == "" || part == "." || part == ".." {
			return "", domain.ErrInvalid
		}
	}
	return clean, nil
}

func typeFor(p string) string {
	t := mime.TypeByExtension(path.Ext(p))
	if t == "" {
		return "application/octet-stream"
	}
	return t
}
