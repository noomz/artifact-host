package domain

import "testing"

func TestCanRead(t *testing.T) {
	owner := UserID("o")
	site := Site{Owner: owner, Team: "t1", Visibility: VisPublic}
	if !CanRead(nil, site) {
		t.Fatal("public should allow anonymous")
	}

	site.Visibility = VisOwner
	if CanRead(nil, site) {
		t.Fatal("owner site should deny anonymous")
	}
	if !CanRead(&Principal{User: owner}, site) {
		t.Fatal("owner should read own site")
	}
	if CanRead(&Principal{User: "other"}, site) {
		t.Fatal("other user should not read owner site")
	}

	site.Visibility = VisTeam
	if CanRead(&Principal{User: "x", Teams: []TeamID{"nope"}}, site) {
		t.Fatal("wrong team denied")
	}
	if !CanRead(&Principal{User: "x", Teams: []TeamID{"t1"}}, site) {
		t.Fatal("team member should read")
	}
	if !CanRead(&Principal{User: owner}, site) {
		t.Fatal("owner should read team site")
	}
	if !CanRead(&Principal{Admin: true}, site) {
		t.Fatal("admin should read")
	}
}

func TestCanWrite(t *testing.T) {
	site := Site{Owner: "o"}
	if CanWrite(Principal{}, &site) {
		t.Fatal("empty principal cannot write")
	}
	if !CanWrite(Principal{User: "n"}, nil) {
		t.Fatal("any user can create")
	}
	if CanWrite(Principal{User: "n"}, &site) {
		t.Fatal("non-owner cannot republish")
	}
	if !CanWrite(Principal{User: "o"}, &site) {
		t.Fatal("owner can republish")
	}
}

func TestVisibilityCheck(t *testing.T) {
	if VisTeam.Check("") == nil {
		t.Fatal("team visibility needs team id")
	}
	if VisPublic.Check("t") == nil {
		t.Fatal("public cannot carry team id")
	}
	if err := VisOwner.Check(""); err != nil {
		t.Fatal(err)
	}
}
