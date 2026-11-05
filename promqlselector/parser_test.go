package promqlselector

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseMetricSelector_Accept(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []Matcher
	}{
		// Bare metric names
		{"bare ident", "foo", []Matcher{{MatchEqual, MetricNameLabel, "foo"}}},
		{"bare ident underscore", "_foo", []Matcher{{MatchEqual, MetricNameLabel, "_foo"}}},
		{"bare ident colon", "foo:bar", []Matcher{{MatchEqual, MetricNameLabel, "foo:bar"}}},
		{"bare ident leading colon", ":foo", []Matcher{{MatchEqual, MetricNameLabel, ":foo"}}},
		{"bare digits tail", "foo_123", []Matcher{{MatchEqual, MetricNameLabel, "foo_123"}}},
		{"bare keyword-like sum", "sum", []Matcher{{MatchEqual, MetricNameLabel, "sum"}}},
		{"bare keyword-like offset", "offset", []Matcher{{MatchEqual, MetricNameLabel, "offset"}}},

		// Empty / metric-only brace combinations
		{"empty braces", "{}", nil},
		{"ident with empty braces", "foo{}", []Matcher{{MatchEqual, MetricNameLabel, "foo"}}},

		// Single matcher, all operators
		{"eq", `{a="b"}`, []Matcher{{MatchEqual, "a", "b"}}},
		{"neq", `{a!="b"}`, []Matcher{{MatchNotEqual, "a", "b"}}},
		{"regex", `{a=~"b.*"}`, []Matcher{{MatchRegexp, "a", "b.*"}}},
		{"not-regex", `{a!~"b.*"}`, []Matcher{{MatchNotRegexp, "a", "b.*"}}},

		// Multiple matchers, trailing comma, whitespace
		{"two matchers", `{a="b",c="d"}`, []Matcher{
			{MatchEqual, "a", "b"}, {MatchEqual, "c", "d"},
		}},
		{"trailing comma", `{a="b",}`, []Matcher{{MatchEqual, "a", "b"}}},
		{"trailing comma two", `{a="b",c="d",}`, []Matcher{
			{MatchEqual, "a", "b"}, {MatchEqual, "c", "d"},
		}},
		{"spaces around ops", `{ a = "b" , c = "d" }`, []Matcher{
			{MatchEqual, "a", "b"}, {MatchEqual, "c", "d"},
		}},
		{"newlines in selector", "{\n\ta=\"b\",\n\tc=\"d\"\n}", []Matcher{
			{MatchEqual, "a", "b"}, {MatchEqual, "c", "d"},
		}},

		// Metric name + matchers (metric name appended last)
		{"metric plus match", `foo{a="b"}`, []Matcher{
			{MatchEqual, "a", "b"},
			{MatchEqual, MetricNameLabel, "foo"},
		}},
		{"metric plus two matches", `foo{a="b",c=~"d.*"}`, []Matcher{
			{MatchEqual, "a", "b"},
			{MatchRegexp, "c", "d.*"},
			{MatchEqual, MetricNameLabel, "foo"},
		}},
		{"explicit __name__", `{__name__="foo"}`, []Matcher{
			{MatchEqual, MetricNameLabel, "foo"},
		}},
		{"duplicate __name__", `foo{__name__="bar"}`, []Matcher{
			{MatchEqual, MetricNameLabel, "bar"},
			{MatchEqual, MetricNameLabel, "foo"},
		}},
		{"empty matcher value accepted", `{a=""}`, []Matcher{{MatchEqual, "a", ""}}},

		// Label-name edge cases (keywords allowed as label names)
		{"keyword label sum", `{sum="x"}`, []Matcher{{MatchEqual, "sum", "x"}}},
		{"keyword label by", `{by="x"}`, []Matcher{{MatchEqual, "by", "x"}}},
		{"keyword label offset", `{offset="x"}`, []Matcher{{MatchEqual, "offset", "x"}}},

		// Non-double-quoted string styles (double-quoted is exercised throughout).
		{"single-quoted", `{a='b'}`, []Matcher{{MatchEqual, "a", "b"}}},
		{"backtick raw", "{a=`b\\nc`}", []Matcher{{MatchEqual, "a", `b\nc`}}},

		// Escape sequences
		{"escape quote", `{a="\""}`, []Matcher{{MatchEqual, "a", `"`}}},
		{"escape newline", `{a="\n"}`, []Matcher{{MatchEqual, "a", "\n"}}},
		{"escape tab", `{a="\t"}`, []Matcher{{MatchEqual, "a", "\t"}}},
		{"escape hex", `{a="\xFF"}`, []Matcher{{MatchEqual, "a", "\xff"}}},
		{"escape unicode 4", `{a="\u00e9"}`, []Matcher{{MatchEqual, "a", "é"}}},
		{"escape unicode 8", `{a="\U0001F600"}`, []Matcher{{MatchEqual, "a", "😀"}}},
		{"escape octal", `{a="\377"}`, []Matcher{{MatchEqual, "a", "\xff"}}},
		{"escape backslash", `{a="\\"}`, []Matcher{{MatchEqual, "a", `\`}}},

		// UTF-8 in values
		{"utf8 value", `{a="héllo"}`, []Matcher{{MatchEqual, "a", "héllo"}}},
		{"emoji value", `{a="🦀"}`, []Matcher{{MatchEqual, "a", "🦀"}}},

		// Comments
		{"trailing comment", "foo # comment", []Matcher{{MatchEqual, MetricNameLabel, "foo"}}},
		{"leading comment", "# start\nfoo", []Matcher{{MatchEqual, MetricNameLabel, "foo"}}},
		{"comment inside braces", "{ # hi\n a=\"b\" # bye\n}", []Matcher{
			{MatchEqual, "a", "b"},
		}},
		{"hash inside string", `{a="# not a comment"}`, []Matcher{
			{MatchEqual, "a", "# not a comment"},
		}},

		// Complex regexes
		{"regex alt", `{a=~"foo|bar"}`, []Matcher{{MatchRegexp, "a", "foo|bar"}}},
		{"regex empty", `{a=~""}`, []Matcher{{MatchRegexp, "a", ""}}},
		{"regex case-insensitive", `{a=~"(?i)x"}`, []Matcher{{MatchRegexp, "a", "(?i)x"}}},
		{"regex char class", `{a=~"[0-9]+"}`, []Matcher{{MatchRegexp, "a", "[0-9]+"}}},

		// Common label-policy shapes used by downstream callers.
		{"label policy env prod", `{env="prod"}`, []Matcher{{MatchEqual, "env", "prod"}}},
		{"label policy env dev", `{env="dev"}`, []Matcher{{MatchEqual, "env", "dev"}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseMetricSelector(c.input)
			require.NoError(t, err)
			require.Equal(t, c.want, got)
		})
	}
}

func TestParseMetricSelector_Reject(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		// Malformed syntax
		{"empty input", ""},
		{"only whitespace", "   "},
		{"only comment", "# no selector"},
		{"unterminated brace open", `{env=`},
		{"unterminated brace missing close", `{a="b"`},
		{"lone comma", `{,}`},
		{"double comma", `{a="b",,c="d"}`},
		{"missing value", `{a=}`},
		{"missing op", `{a "b"}`},
		{"missing label", `{="b"}`},
		{"trailing garbage after metric", "foo xx"},
		{"trailing garbage after braces", `{a="b"} xx`},
		{"stray close brace", `foo}`},
		{"bare bang", `{a!b}`},

		// Quoted label names (PromQL v3) — must reject
		{"quoted label name", `{"foo"="bar"}`},

		// Rejected PromQL constructs
		{"range selector", `foo[5m]`},
		{"offset", `foo offset 1m`},
		{"at modifier", `foo @ 0`},
		{"binary op", `foo + bar`},
		{"function call", `sum(foo)`},
		{"number literal", `42`},
		{"duration", `5m`},

		// Bad strings
		{"unterminated quoted", `{a="b`},
		{"unterminated raw", "{a=`b"},
		{"newline in quoted", "{a=\"b\nc\"}"},
		{"bad escape", `{a="\q"}`},
		{"incomplete hex", `{a="\x"}`},
		{"bad hex", `{a="\xZZ"}`},
		{"out of range U", `{a="\U12345678"}`},
		{"bad octal start", `{a="\8"}`},
		{"octal overflow", `{a="\400"}`},

		// Invalid regex
		{"invalid regex star", `{a=~"*"}`},
		{"invalid regex group", `{a=~"(unclosed"}`},

		// Label names with invalid characters
		{"colon in label", `{foo:bar="x"}`},
		{"leading colon label", `{:foo="x"}`},

		// Multiple metric names
		{"double metric", `foo bar`},

		// Reserved keywords rejected as bare metric names (parity with
		// upstream metric_identifier grammar rule).
		{"reserved metric on", "on"},
		{"reserved metric atan2", "atan2"},
		{"reserved metric ignoring", "ignoring"},
		{"reserved metric group_left", "group_left"},
		{"reserved metric group_right", "group_right"},
		{"reserved metric bool", "bool"},
		{"reserved metric inf", "inf"},
		{"reserved metric nan", "nan"},
		{"reserved metric inf case-insensitive", "Inf"},
		{"reserved metric on with braces", `on{a="b"}`},

		// Invalid UTF-8 bytes raw (not via escape) in strings.
		{"invalid utf8 in quoted", "{a=\"\x96\"}"},
		{"invalid utf8 in single-quoted", "{a='\x96'}"},
		{"invalid utf8 in backtick", "{a=`\x96`}"},

		// Surrogate escape (parity: upstream rejects at lex time).
		{"surrogate u escape", `{a="\uD800"}`},
		{"surrogate U escape", `{a="\U0000D800"}`},

		// Newline in quoted string (upstream: unterminated at lex).
		{"literal newline in quoted", "{a=\"foo\nbar\"}"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseMetricSelector(c.input)
			require.Error(t, err)
			require.True(t, errors.Is(err, ErrParseSelector),
				"expected error to wrap ErrParseSelector, got %v", err)
		})
	}
}

func TestParseError_Format(t *testing.T) {
	_, err := ParseMetricSelector("foo bar")
	require.Error(t, err)
	var pe *ParseError
	require.True(t, errors.As(err, &pe))
	require.Equal(t, 1, pe.Line)
	require.Equal(t, 5, pe.Col)
}

func TestParseError_Multiline(t *testing.T) {
	// the problem is on line 2, col 1 (the stray `}` just after the newline).
	_, err := ParseMetricSelector("{a=\"b\"}\n}")
	require.Error(t, err)
	var pe *ParseError
	require.True(t, errors.As(err, &pe))
	require.Equal(t, 2, pe.Line)
	require.Equal(t, 1, pe.Col)
}
