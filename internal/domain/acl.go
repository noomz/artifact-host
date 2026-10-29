package domain

func CanRead(p *Principal, s Site) bool {
	if p != nil && p.Admin {
		return true
	}
	switch s.Visibility {
	case VisPublic:
		return true
	case VisOwner:
		return p != nil && p.User == s.Owner
	case VisTeam:
		if p == nil {
			return false
		}
		if p.User == s.Owner {
			return true
		}
		return s.Team != "" && InTeam(p.Teams, s.Team)
	default:
		return false
	}
}

func CanWrite(p Principal, existing *Site) bool {
	if p.Admin {
		return true
	}
	if p.User == "" {
		return false
	}
	if existing == nil {
		return true
	}
	return existing.Owner == p.User
}
