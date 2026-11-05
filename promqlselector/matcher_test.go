package promqlselector

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchType_String(t *testing.T) {
	cases := []struct {
		typ  MatchType
		want string
	}{
		{MatchEqual, "="},
		{MatchNotEqual, "!="},
		{MatchRegexp, "=~"},
		{MatchNotRegexp, "!~"},
		{MatchType(99), "MatchType(99)"},
	}
	for _, c := range cases {
		require.Equal(t, c.want, c.typ.String(), "MatchType(%d).String()", int(c.typ))
	}
}

func TestMatcher_String(t *testing.T) {
	cases := []struct {
		m    Matcher
		want string
	}{
		{Matcher{MatchEqual, "env", "prod"}, `env="prod"`},
		{Matcher{MatchNotEqual, "env", "staging"}, `env!="staging"`},
		{Matcher{MatchRegexp, "path", `/api/.*`}, `path=~"/api/.*"`},
		{Matcher{MatchNotRegexp, "host", `^x`}, `host!~"^x"`},
		{Matcher{MatchEqual, MetricNameLabel, "up"}, `__name__="up"`},
		{Matcher{MatchEqual, "msg", `say "hi"`}, `msg="say \"hi\""`},
	}
	for _, c := range cases {
		require.Equal(t, c.want, c.m.String())
	}
}

func TestParseError_ErrorString(t *testing.T) {
	_, err := ParseMetricSelector("foo bar")
	require.Error(t, err)
	var pe *ParseError
	require.True(t, errors.As(err, &pe))
	require.Contains(t, pe.Error(), "1:5: parse error:")
}
