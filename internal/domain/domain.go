package domain

import "errors"

type UserID string
type TeamID string
type SiteID string
type VersionID string

type Visibility string

const (
	VisPublic Visibility = "public"
	VisOwner  Visibility = "owner"
	VisTeam   Visibility = "team"
)

type Site struct {
	ID         SiteID
	Owner      UserID
	Team       TeamID
	Visibility Visibility
	Current    VersionID
}

type User struct {
	ID   UserID
	Name string
}

type Principal struct {
	User  UserID
	Teams []TeamID
	Admin bool
}

type File struct {
	Path        string
	Body        []byte
	ContentType string
}

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrNotFound     = errors.New("not found")
	ErrInvalid      = errors.New("invalid")
)

func ParseVisibility(s string) (Visibility, error) {
	switch Visibility(s) {
	case VisPublic, VisOwner, VisTeam:
		return Visibility(s), nil
	default:
		return "", ErrInvalid
	}
}

func (v Visibility) Check(team TeamID) error {
	if v == VisTeam && team == "" {
		return ErrInvalid
	}
	if v != VisTeam && team != "" {
		return ErrInvalid
	}
	return nil
}

func InTeam(teams []TeamID, id TeamID) bool {
	for _, t := range teams {
		if t == id {
			return true
		}
	}
	return false
}
