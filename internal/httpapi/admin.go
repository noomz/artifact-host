package httpapi

import (
	"crypto/subtle"
	"embed"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/noomz/artifact-host/internal/domain"
)

//go:embed templates/*.html
var adminFS embed.FS

var (
	tplLogin     = template.Must(template.ParseFS(adminFS, "templates/login.html"))
	tplDashboard = template.Must(template.ParseFS(adminFS, "templates/dashboard.html"))
)

const (
	cookieAdmin = "ah_admin"
	cookieFlash = "ah_flash"
)

type teamView struct {
	Team    domain.Team
	Members []domain.User
}

type dashData struct {
	Users      []domain.User
	Teams      []teamView
	Sites      []domain.Site
	Base       string
	Err        string
	FlashToken string
	FlashName  string
}

func (s *Server) mountAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/login", s.adminLoginGET)
	mux.HandleFunc("POST /admin/login", s.adminLoginPOST)
	mux.HandleFunc("POST /admin/logout", s.adminLogout)
	mux.HandleFunc("GET /admin", s.adminHome)
	mux.HandleFunc("POST /admin/users", s.adminCreateUser)
	mux.HandleFunc("POST /admin/users/{id}/rotate", s.adminRotateUser)
	mux.HandleFunc("POST /admin/users/{id}/delete", s.adminDeleteUser)
	mux.HandleFunc("POST /admin/teams", s.adminCreateTeam)
	mux.HandleFunc("POST /admin/teams/{id}/delete", s.adminDeleteTeam)
	mux.HandleFunc("POST /admin/teams/{id}/members", s.adminAddMember)
	mux.HandleFunc("POST /admin/teams/{id}/members/{uid}/delete", s.adminRemoveMember)
	mux.HandleFunc("POST /admin/sites/{id}/delete", s.adminDeleteSite)
}

func (s *Server) adminLoginGET(w http.ResponseWriter, r *http.Request) {
	if s.cookieAdminOK(r) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	_ = tplLogin.Execute(w, map[string]string{"Err": r.URL.Query().Get("err")})
}

func (s *Server) adminLoginPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/login?err="+url.QueryEscape("bad form"), http.StatusSeeOther)
		return
	}
	tok := strings.TrimSpace(r.FormValue("token"))
	if !s.adminEq(tok) {
		http.Redirect(w, r, "/admin/login?err="+url.QueryEscape("bad token"), http.StatusSeeOther)
		return
	}
	http.SetCookie(w, s.adminCookie(r, tok, 86400*14))
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, s.adminCookie(r, "", -1))
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (s *Server) adminHome(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	data, err := s.loadDash(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data.Err = r.URL.Query().Get("err")
	data.FlashName = r.URL.Query().Get("issued")
	if c, err := r.Cookie(cookieFlash); err == nil && c.Value != "" {
		data.FlashToken = c.Value
		http.SetCookie(w, s.flashCookie(r, "", -1))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = tplDashboard.Execute(w, data)
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.adminErr(w, r, "bad form")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.adminErr(w, r, "name required")
		return
	}
	raw, hash := s.newToken()
	id := s.newUserID()
	if err := s.Host.Meta.CreateUser(r.Context(), id, name, hash); err != nil {
		s.adminErr(w, r, err.Error())
		return
	}
	http.SetCookie(w, s.flashCookie(r, raw, 60))
	http.Redirect(w, r, "/admin?issued="+url.QueryEscape(name), http.StatusSeeOther)
}

func (s *Server) adminRotateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := domain.UserID(r.PathValue("id"))
	u, err := s.Host.Meta.User(r.Context(), id)
	if err != nil {
		s.adminErr(w, r, err.Error())
		return
	}
	raw, hash := s.newToken()
	if err := s.Host.Meta.SetUserTokenHash(r.Context(), id, hash); err != nil {
		s.adminErr(w, r, err.Error())
		return
	}
	http.SetCookie(w, s.flashCookie(r, raw, 60))
	http.Redirect(w, r, "/admin?issued="+url.QueryEscape(u.Name), http.StatusSeeOther)
}

func (s *Server) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Host.Meta.DeleteUser(r.Context(), domain.UserID(r.PathValue("id"))); err != nil {
		if err == domain.ErrInvalid {
			s.adminErr(w, r, "user still owns sites")
			return
		}
		s.adminErr(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminCreateTeam(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.adminErr(w, r, "bad form")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.adminErr(w, r, "name required")
		return
	}
	if err := s.Host.Meta.CreateTeam(r.Context(), s.newTeamID(), name); err != nil {
		s.adminErr(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminDeleteTeam(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Host.Meta.DeleteTeam(r.Context(), domain.TeamID(r.PathValue("id"))); err != nil {
		if err == domain.ErrInvalid {
			s.adminErr(w, r, "team still used by sites")
			return
		}
		s.adminErr(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminAddMember(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.adminErr(w, r, "bad form")
		return
	}
	uid := domain.UserID(r.FormValue("user_id"))
	if uid == "" {
		s.adminErr(w, r, "user required")
		return
	}
	if _, err := s.Host.Meta.User(r.Context(), uid); err != nil {
		s.adminErr(w, r, err.Error())
		return
	}
	if err := s.Host.Meta.AddMember(r.Context(), domain.TeamID(r.PathValue("id")), uid); err != nil {
		s.adminErr(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminRemoveMember(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Host.Meta.RemoveMember(r.Context(), domain.TeamID(r.PathValue("id")), domain.UserID(r.PathValue("uid"))); err != nil {
		s.adminErr(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminDeleteSite(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Host.Meta.DeleteSite(r.Context(), domain.SiteID(r.PathValue("id"))); err != nil {
		s.adminErr(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) loadDash(r *http.Request) (dashData, error) {
	ctx := r.Context()
	users, err := s.Host.Meta.ListUsers(ctx)
	if err != nil {
		return dashData{}, err
	}
	teams, err := s.Host.Meta.ListTeams(ctx)
	if err != nil {
		return dashData{}, err
	}
	var tv []teamView
	for _, t := range teams {
		ms, err := s.Host.Meta.Members(ctx, t.ID)
		if err != nil {
			return dashData{}, err
		}
		tv = append(tv, teamView{Team: t, Members: ms})
	}
	sites, err := s.Host.Meta.ListSites(ctx)
	if err != nil {
		return dashData{}, err
	}
	return dashData{Users: users, Teams: tv, Sites: sites, Base: s.BaseURL}, nil
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if s.cookieAdminOK(r) || s.adminOK(r) {
		return true
	}
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
	return false
}

func (s *Server) adminErr(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/admin?err="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (s *Server) cookieAdminOK(r *http.Request) bool {
	c, err := r.Cookie(cookieAdmin)
	if err != nil {
		return false
	}
	return s.adminEq(c.Value)
}

func (s *Server) adminEq(got string) bool {
	if s.Admin == "" || got == "" || len(got) != len(s.Admin) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.Admin)) == 1
}

func (s *Server) adminCookie(r *http.Request, val string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     cookieAdmin,
		Value:    val,
		Path:     "/admin",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   forwardedHTTPS(r),
	}
}

func (s *Server) flashCookie(r *http.Request, val string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     cookieFlash,
		Value:    val,
		Path:     "/admin",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   forwardedHTTPS(r),
	}
}

func forwardedHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

