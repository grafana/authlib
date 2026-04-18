// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file contains regression test cases ported from
// github.com/prometheus/prometheus/promql/parser/parse_test.go (pinned
// version v1.8.2-0.20220315145411-881111fec433 at commit 881111fec433), from
// the testExpr table (selector-shaped inputs) and TestExtractSelectors. See
// LICENSE-PROMETHEUS in this directory.
//
// Cases are adapted for ParseMetricSelector, which uses the same grammar as
// upstream's vector_selector rule but skips checkAST — so selectors like
// {} or foo{__name__="bar"} that upstream's ParseExpr rejects at the AST
// check layer are accepted here, matching upstream's ParseMetricSelector.

package promqlselector

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// promAccept lists selector inputs that upstream ParseMetricSelector accepts,
// adapted from upstream testExpr entries whose expected is a VectorSelector
// (or from TestExtractSelectors directly).
var promAccept = []struct {
	name  string
	input string
	want  []Matcher
}{
	// testExpr: pure vector selectors
	{"foo bare", "foo", []Matcher{{MatchEqual, MetricNameLabel, "foo"}}},
	{"min bare (keyword allowed as metric name)", "min", []Matcher{{MatchEqual, MetricNameLabel, "min"}}},
	{"foo:bar", `foo:bar{a="bc"}`, []Matcher{
		{MatchEqual, "a", "bc"},
		{MatchEqual, MetricNameLabel, "foo:bar"},
	}},
	{"keyword as label name NaN", `foo{NaN='bc'}`, []Matcher{
		{MatchEqual, "NaN", "bc"},
		{MatchEqual, MetricNameLabel, "foo"},
	}},
	{"right brace inside string", `foo{bar='}'}`, []Matcher{
		{MatchEqual, "bar", "}"},
		{MatchEqual, MetricNameLabel, "foo"},
	}},
	{"four matchers all ops", `foo{a="b", foo!="bar", test=~"test", bar!~"baz"}`, []Matcher{
		{MatchEqual, "a", "b"},
		{MatchNotEqual, "foo", "bar"},
		{MatchRegexp, "test", "test"},
		{MatchNotRegexp, "bar", "baz"},
		{MatchEqual, MetricNameLabel, "foo"},
	}},
	{"four matchers trailing comma", `foo{a="b", foo!="bar", test=~"test", bar!~"baz",}`, []Matcher{
		{MatchEqual, "a", "b"},
		{MatchNotEqual, "foo", "bar"},
		{MatchRegexp, "test", "test"},
		{MatchNotRegexp, "bar", "baz"},
		{MatchEqual, MetricNameLabel, "foo"},
	}},

	// Upstream ParseExpr rejects these at checkAST, but ParseMetricSelector
	// skips checkAST and accepts them (parity-verified).
	{"empty braces (checkAST-skip)", `{}`, nil},
	{"single empty match (checkAST-skip)", `{x=""}`, []Matcher{{MatchEqual, "x", ""}}},
	{"match-all regex (checkAST-skip)", `{x=~".*"}`, []Matcher{{MatchRegexp, "x", ".*"}}},
	{"match-any-nonempty not-regex (checkAST-skip)", `{x!~".+"}`, []Matcher{{MatchNotRegexp, "x", ".+"}}},
	{"not-equal (checkAST-skip)", `{x!="a"}`, []Matcher{{MatchNotEqual, "x", "a"}}},
	{"duplicate __name__ (checkAST-skip)", `foo{__name__="bar"}`, []Matcher{
		{MatchEqual, MetricNameLabel, "bar"},
		{MatchEqual, MetricNameLabel, "foo"},
	}},

	// TestExtractSelectors direct ParseMetricSelector inputs
	{"extract-selectors foo", `foo`, []Matcher{{MatchEqual, MetricNameLabel, "foo"}}},
	{"extract-selectors foo with bar=baz", `foo{bar="baz"}`, []Matcher{
		{MatchEqual, "bar", "baz"},
		{MatchEqual, MetricNameLabel, "foo"},
	}},
}

// promReject lists inputs upstream rejects at the ParseMetricSelector layer
// (either at lex or at the vector_selector grammar rule — not at checkAST).
var promReject = []struct {
	name  string
	input string
}{
	{"lone open brace", `{`},
	{"lone close brace", `}`},
	{"metric then open brace EOF", `some{`},
	{"stray close brace after ident", `some}`},
	{"value not string", `some_metric{a=b}`},
	{"colon in label name", `some_metric{a:b="b"}`},
	{"star op", `foo{a*"b"}`},
	{"gte op", `foo{a>="b"}`},
	{"invalid utf8 in value", "some_metric{a=\"\xff\"}"},
	{"missing operator", `foo{gibberish}`},
	{"numeric label", `foo{1}`},
	{"empty matcher", `foo{__name__= =}`},
	{"lone comma matcher", `foo{,}`},
	{"double equals op", `foo{__name__ == "bar"}`},
	{"trailing ident inside braces", `foo{__name__="bar" lol}`},
	{"matrix selector", "test[5s]"},
	{"matrix minute", "test[5m]"},
	{"vector plus offset", `foo offset 5m`},
	{"vector plus at-modifier", `foo @ 1603774568`},
	{"vector plus at-modifier Inf (upstream errors)", `foo @ +Inf`},
}

// promParityGaps lists inputs where upstream ParseMetricSelector's behavior
// is NOT exercised by upstream's own test suite, but which this package's
// parity harness surfaced as divergence points when we ran random and
// generated corpora through both implementations side-by-side. Keep these
// here as explicit regression anchors: if we ever change lex/parse logic,
// these are the cases a one-off bug is most likely to re-introduce.
//
// Sources of truth:
//   - Reserved-keyword rejects: upstream grammar rule `metric_identifier`
//     in generated_parser.y omits ON, IGNORING, GROUP_LEFT, GROUP_RIGHT,
//     BOOL, ATAN2, and the NUMBER-aliased INF/NAN from the accepted set,
//     with keyword lookup case-insensitive (strings.ToLower in lex.go).
//   - Surrogate escapes: upstream lexer lexEscape rejects
//     0xD800 <= x < 0xE000 at scan time, before reaching the parser.
//   - Invalid raw UTF-8 in strings: upstream lexString / lexRawString emit
//     "invalid UTF-8 rune" on utf8.RuneError during scan.
var promParityGaps = []struct {
	name  string
	input string
}{
	// Reserved keywords rejected as bare metric names.
	{"bare metric on", "on"},
	{"bare metric ON (case-insensitive)", "ON"},
	{"bare metric atan2", "atan2"},
	{"bare metric ignoring", "ignoring"},
	{"bare metric group_left", "group_left"},
	{"bare metric group_right", "group_right"},
	{"bare metric bool", "bool"},
	{"bare metric inf", "inf"},
	{"bare metric INF (case-insensitive)", "Inf"},
	{"bare metric nan", "nan"},
	{"bare metric NaN (case-insensitive)", "NaN"},
	{"bare metric on with braces", `on{a="b"}`},
	{"bare metric ignoring with braces", `ignoring{a="b"}`},

	// Surrogate code points in \u and \U escapes (upstream lex rejects; we
	// ported an explicit surrogate-range check into Unquote to match).
	{"surrogate u escape low", `{a="\uD800"}`},
	{"surrogate u escape high", `{a="\uDFFF"}`},
	{"surrogate U escape", `{a="\U0000D800"}`},
	{"surrogate in single-quoted", `{a='\uD800'}`},

	// Raw invalid UTF-8 bytes in string bodies (not via \x escape).
	// Upstream's "\xff" testExpr case is in promReject already; these
	// add the single-quoted and backtick variants and adjacent byte values
	// to pin the check.
	{"raw 0x96 in double-quoted", "{a=\"\x96\"}"},
	{"raw 0xa7 in single-quoted", "{a='\xa7'}"},
	{"raw 0xfe in backtick", "{a=`\xfe`}"},
	{"raw 0x80 midword", "{a=\"fo\x80o\"}"},
}

func TestParseMetricSelector_UpstreamAccept(t *testing.T) {
	for _, c := range promAccept {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseMetricSelector(c.input)
			require.NoError(t, err)
			require.Equal(t, c.want, got)
		})
	}
}

func TestParseMetricSelector_UpstreamReject(t *testing.T) {
	for _, c := range promReject {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseMetricSelector(c.input)
			require.Error(t, err)
			require.True(t, errors.Is(err, ErrParseSelector),
				"expected error to wrap ErrParseSelector, got %v", err)
		})
	}
}

func TestParseMetricSelector_ParityGaps(t *testing.T) {
	for _, c := range promParityGaps {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseMetricSelector(c.input)
			require.Error(t, err)
			require.True(t, errors.Is(err, ErrParseSelector),
				"expected error to wrap ErrParseSelector, got %v", err)
		})
	}
}
