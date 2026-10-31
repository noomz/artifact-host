package domain

import (
	"strings"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		invalid     bool
	}{
		{"  Café  ", "Café", false},
		{" \t ", "", false},
		{strings.Repeat("界", 200), strings.Repeat("界", 200), false},
		{strings.Repeat("界", 201), "", true},
		{string([]byte{0xff}), "", true},
	} {
		got, err := NormalizeName(tc.input)
		if (err != nil) != tc.invalid || got != tc.want {
			t.Errorf("NormalizeName(%q) = %q, %v", tc.input, got, err)
		}
	}
}
