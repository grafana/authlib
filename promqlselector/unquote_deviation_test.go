package promqlselector

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUnquote_RejectsSurrogateEscapes directly exercises the one deviation
// this package's unquote.go has from upstream strutil.Unquote: \u and \U
// escapes that decode to surrogate code points (0xD800-0xDFFF) must error.
// Upstream's PromQL lexer rejects these at scan time before strutil sees
// them, so upstream's quote_test.go does not cover it. This test pins the
// deviation so a future refactor of unquote.go cannot silently revert it.
func TestUnquote_RejectsSurrogateEscapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"u low surrogate boundary", `"\uD800"`},
		{"u high surrogate boundary", `"\uDFFF"`},
		{"u mid surrogate", `"\uDABC"`},
		{"U low surrogate", `"\U0000D800"`},
		{"U high surrogate", `"\U0000DFFF"`},
		{"u surrogate in single-quoted", `'\uD800'`},
		{"U surrogate in single-quoted", `'\U0000D800'`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := Unquote(c.in)
			require.Empty(t, out, "Unquote(%#q)", c.in)
			require.EqualError(t, err, ErrSyntax.Error(), "Unquote(%#q)", c.in)
		})
	}
}

// TestUnquote_AcceptsNonSurrogateBoundaries pins the inverse: code points
// adjacent to the surrogate range (just below 0xD800 and just above 0xDFFF)
// must still parse, so the check is exactly bounded.
func TestUnquote_AcceptsNonSurrogateBoundaries(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"u just below surrogate range", `"퟿"`, "퟿"},
		{"u just above surrogate range", `""`, ""},
		{"U just below surrogate range", `"\U0000D7FF"`, "퟿"},
		{"U just above surrogate range", `"\U0000E000"`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := Unquote(c.in)
			require.NoError(t, err)
			require.Equal(t, c.want, out)
		})
	}
}
