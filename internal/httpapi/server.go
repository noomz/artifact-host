package httpapi

import (
	"archive/tar"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/noomz/artifact-host/internal/domain"
	"github.com/noomz/artifact-host/internal/sites"
)

const maxBody = 32 << 20

type Server struct {
	Host      *sites.Host
	Admin     string
	BaseURL   string
	newUserID func() domain.UserID
	newTeamID func() domain.TeamID
	newToken  func() (raw string, hash []byte)
}

func New(h *sites.Host, admin, baseURL string) *Server {
	return &Server{
		Host:      h,
		Admin:     admin,
		BaseURL:   strings.TrimRight(baseURL, "/"),
		newUserID: func() domain.UserID { return domain.UserID(sites.NewID()) },
		newTeamID: func() domain.TeamID { return domain.TeamID(sites.NewID()) },
		newToken:  newToken,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /v1/users", s.createUser)
	mux.HandleFunc("POST /v1/teams", s.createTeam)
	mux.HandleFunc("POST /v1/teams/{id}/members", s.addMember)
	mux.HandleFunc("POST /v1/sites", s.publish)
	mux.HandleFunc("GET /s/{id}", s.serve)
	mux.HandleFunc("GET /s/{id}/{path...}", s.serve)
	return mux
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(r) {
		writeErr(w, domain.ErrUnauthorized)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		writeErr(w, domain.ErrInvalid)
		return
	}
	raw, hash := s.newToken()
	id := s.newUserID()
	if err := s.Host.Meta.CreateUser(r.Context(), id, body.Name, hash); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": string(id), "token": raw, "name": body.Name})
}

func (s *Server) createTeam(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(r) {
		writeErr(w, domain.ErrUnauthorized)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		writeErr(w, domain.ErrInvalid)
		return
	}
	id := s.newTeamID()
	if err := s.Host.Meta.CreateTeam(r.Context(), id, body.Name); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": string(id), "name": body.Name})
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(r) {
		writeErr(w, domain.ErrUnauthorized)
		return
	}
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.UserID == "" {
		writeErr(w, domain.ErrInvalid)
		return
	}
	team := domain.TeamID(r.PathValue("id"))
	if _, err := s.Host.Meta.User(r.Context(), domain.UserID(body.UserID)); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.Host.Meta.AddMember(r.Context(), team, domain.UserID(body.UserID)); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) publish(w http.ResponseWriter, r *http.Request) {
	actor, err := s.principal(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	vis, err := domain.ParseVisibility(headerOr(r, "Visibility", "X-Visibility", "public"))
	if err != nil {
		writeErr(w, err)
		return
	}
	files, err := readTarFiles(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	out, err := s.Host.Publish(r.Context(), actor, sites.PublishIn{
		Site:       domain.SiteID(headerOr(r, "Site-Id", "X-Site-Id", "")),
		Visibility: vis,
		Team:       domain.TeamID(headerOr(r, "Team-Id", "X-Team-Id", "")),
		Files:      files,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"id":      string(out.Site),
		"version": string(out.Version),
		"url":     s.BaseURL + "/s/" + string(out.Site) + "/",
	})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	actor, err := s.optionalPrincipal(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	p := r.PathValue("path")
	body, ctype, err := s.Host.Open(r.Context(), actor, domain.SiteID(r.PathValue("id")), p)
	if err != nil {
		writeErr(w, err)
		return
	}
	defer body.Close()
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, body)
}

func (s *Server) adminOK(r *http.Request) bool {
	if s.Admin == "" {
		return false
	}
	got, ok := bearer(r)
	if !ok {
		return false
	}
	if len(got) != len(s.Admin) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.Admin)) == 1
}

func (s *Server) principal(r *http.Request) (domain.Principal, error) {
	p, err := s.optionalPrincipal(r)
	if err != nil {
		return domain.Principal{}, err
	}
	if p == nil {
		return domain.Principal{}, domain.ErrUnauthorized
	}
	return *p, nil
}

func (s *Server) optionalPrincipal(r *http.Request) (*domain.Principal, error) {
	raw, ok := bearer(r)
	if !ok {
		return nil, nil
	}
	if s.Admin != "" && len(raw) == len(s.Admin) && subtle.ConstantTimeCompare([]byte(raw), []byte(s.Admin)) == 1 {
		return &domain.Principal{Admin: true}, nil
	}
	sum := sha256.Sum256([]byte(raw))
	u, err := s.Host.Meta.UserByTokenHash(r.Context(), sum[:])
	if err != nil {
		return nil, err
	}
	teams, err := s.Host.Meta.TeamsForUser(r.Context(), u.ID)
	if err != nil {
		return nil, err
	}
	return &domain.Principal{User: u.ID, Teams: teams}, nil
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	t := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if t == "" {
		return "", false
	}
	return t, true
}

func headerOr(r *http.Request, a, b, def string) string {
	if v := strings.TrimSpace(r.Header.Get(a)); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get(b)); v != "" {
		return v
	}
	return def
}

func readTarFiles(r *http.Request) ([]domain.File, error) {
	tr := tar.NewReader(io.LimitReader(r.Body, maxBody))
	var files []domain.File
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, domain.ErrInvalid
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size > maxBody {
			return nil, domain.ErrInvalid
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, domain.ErrInvalid
		}
		files = append(files, domain.File{Path: hdr.Name, Body: body})
	}
	return files, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, domain.ErrUnauthorized):
		code = http.StatusUnauthorized
	case errors.Is(err, domain.ErrForbidden):
		code = http.StatusForbidden
	case errors.Is(err, domain.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, domain.ErrInvalid):
		code = http.StatusBadRequest
	}
	http.Error(w, err.Error(), code)
}

func newToken() (string, []byte) {
	raw := sites.NewID() + sites.NewID()
	sum := sha256.Sum256([]byte(raw))
	return raw, sum[:]
}

func TokenHash(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
