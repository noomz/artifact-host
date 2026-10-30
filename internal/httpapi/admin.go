package httpapi

import (
	"crypto/subtle"
	"embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/noomz/artifact-host/internal/domain"
)

//go:embed templates/*.html
var adminFS embed.FS

var (
	tplLogin     = template.Must(template.ParseFS(adminFS, "templates/login.html"))
	tplDashboard = template.Must(template.ParseFS(adminFS, "templates/dashboard.html"))
	tplIssued    = template.Must(template.ParseFS(adminFS, "templates/issued.html"))
)

var adminErrText = map[string]string{
	"bad_form":       "That form was not valid.",
	"bad_token":      "That token was not accepted.",
	"rate":           "Too many sign-in attempts. Wait and try again.",
	"name":           "A name is required.",
	"user_required":  "Pick a user.",
	"owns_sites":     "That user still owns sites.",
	"team_sites":     "That team is still used by sites.",
}

type teamView struct {
	Team    domain.Team
	Members []domain.User
}

type dashData struct {
	Users []domain.User
	Teams []teamView
	Sites []domain.Site
	Base  string
	Err   string
}

func adminErrMsg(code string) string {
	return adminErrText[code]
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

func adminHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
}

func (s *Server) adminLoginGET(w http.ResponseWriter, r *http.Request) {
	if s.sessionOK(r) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	adminHeaders(w)
	_ = tplLogin.Execute(w, map[string]string{"Err": adminErrMsg(r.URL.Query().Get("err"))})
}

func (s *Server) adminLoginPOST(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.logins.begin(ip) {
		http.Redirect(w, r, "/admin/login?err=rate", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/login?err=bad_form", http.StatusSeeOther)
		return
	}
	tok := strings.TrimSpace(r.FormValue("token"))
	if !s.adminEq(tok) {
		http.Redirect(w, r, "/admin/login?err=bad_token", http.StatusSeeOther)
		return
	}
	s.logins.clear(ip)
	sid, err := s.sessions.issue()
	if err != nil {
		http.Error(w, "session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, s.sessionCookie(r, sid, int(sessionTTL.Seconds())))
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieSession); err == nil {
		s.sessions.revoke(c.Value)
	}
	http.SetCookie(w, s.sessionCookie(r, "", -1))
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
	data.Err = adminErrMsg(r.URL.Query().Get("err"))
	adminHeaders(w)
	_ = tplDashboard.Execute(w, data)
}

func (s *Server) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.adminErr(w, r, "bad_form")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.adminErr(w, r, "name")
		return
	}
	raw, hash := s.newToken()
	id := s.newUserID()
	if err := s.Host.Meta.CreateUser(r.Context(), id, name, hash); err != nil {
		s.adminErr(w, r, "bad_form")
		return
	}
	s.renderIssued(w, name, raw)
}

func (s *Server) adminRotateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	id := domain.UserID(r.PathValue("id"))
	u, err := s.Host.Meta.User(r.Context(), id)
	if err != nil {
		s.adminErr(w, r, "bad_form")
		return
	}
	raw, hash := s.newToken()
	if err := s.Host.Meta.SetUserTokenHash(r.Context(), id, hash); err != nil {
		s.adminErr(w, r, "bad_form")
		return
	}
	s.renderIssued(w, u.Name, raw)
}

func (s *Server) renderIssued(w http.ResponseWriter, name, token string) {
	adminHeaders(w)
	_ = tplIssued.Execute(w, map[string]string{"Name": name, "Token": token})
}

func (s *Server) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Host.Meta.DeleteUser(r.Context(), domain.UserID(r.PathValue("id"))); err != nil {
		if err == domain.ErrInvalid {
			s.adminErr(w, r, "owns_sites")
			return
		}
		s.adminErr(w, r, "bad_form")
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminCreateTeam(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.adminErr(w, r, "bad_form")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.adminErr(w, r, "name")
		return
	}
	if err := s.Host.Meta.CreateTeam(r.Context(), s.newTeamID(), name); err != nil {
		s.adminErr(w, r, "bad_form")
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
			s.adminErr(w, r, "team_sites")
			return
		}
		s.adminErr(w, r, "bad_form")
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminAddMember(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.adminErr(w, r, "bad_form")
		return
	}
	uid := domain.UserID(r.FormValue("user_id"))
	if uid == "" {
		s.adminErr(w, r, "user_required")
		return
	}
	if _, err := s.Host.Meta.User(r.Context(), uid); err != nil {
		s.adminErr(w, r, "bad_form")
		return
	}
	if err := s.Host.Meta.AddMember(r.Context(), domain.TeamID(r.PathValue("id")), uid); err != nil {
		s.adminErr(w, r, "bad_form")
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminRemoveMember(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Host.Meta.RemoveMember(r.Context(), domain.TeamID(r.PathValue("id")), domain.UserID(r.PathValue("uid"))); err != nil {
		s.adminErr(w, r, "bad_form")
		return
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) adminDeleteSite(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Host.DeleteSite(r.Context(), domain.SiteID(r.PathValue("id"))); err != nil {
		s.adminErr(w, r, "bad_form")
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
	if s.sessionOK(r) || s.adminOK(r) {
		return true
	}
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
	return false
}

func (s *Server) adminErr(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, "/admin?err="+code, http.StatusSeeOther)
}

func (s *Server) sessionOK(r *http.Request) bool {
	c, err := r.Cookie(cookieSession)
	if err != nil {
		return false
	}
	return s.sessions.valid(c.Value)
}

func (s *Server) adminEq(got string) bool {
	if s.Admin == "" || got == "" || len(got) != len(s.Admin) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.Admin)) == 1
}

func (s *Server) sessionCookie(r *http.Request, val string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     cookieSession,
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
