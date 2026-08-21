// Package promqlselector implements a minimal, zero-dependency parser for
// PromQL metric selectors.
//
// It is a parity extraction of
// github.com/prometheus/prometheus/promql/parser.ParseMetricSelector pinned
// to v1.8.2-0.20220315145411-881111fec433 (commit 881111fec433). On valid
// inputs the matchers returned are identical in order, name, type, and value
// to the upstream parser. On invalid inputs it rejects the same set of
// strings (though the error messages are not required to match).
//
// Accepted grammar (informal):
//
//	selector       := WS? body WS? EOF
//	body           := metric_name label_matchers?
//	                | label_matchers
//	metric_name    := [a-zA-Z_:][a-zA-Z0-9_:]*
//	label_matchers := '{' WS? ( matcher ( WS? ',' WS? matcher )* ( ',' WS? )? )? '}'
//	matcher        := label_name WS? op WS? string
//	label_name     := [a-zA-Z_][a-zA-Z0-9_]*
//	op             := '=' | '!=' | '=~' | '!~'
//	string         := double-quoted | single-quoted | backtick-raw
//
// Strings support PromQL escape sequences in double and single quotes
// (\a \b \f \n \r \t \v \\ \' \" \xHH \uHHHH \UHHHHHHHH and three-digit
// octal). Backtick strings are raw and may not contain a backtick.
//
// Line comments starting with '#' are permitted anywhere whitespace is.
//
// Explicitly not supported (rejected to match the pinned Prometheus version):
//
//   - Quoted label names (PromQL v3 UTF-8 extension), e.g. {"foo"="bar"}
//   - Range selectors, offsets, @-modifiers
//   - Binary operators, aggregations, function calls, numeric literals
//
// ParseMetricSelector does NOT enforce "at least one non-empty matcher" or
// reject duplicate __name__ matchers; upstream's equivalent check lives in
// checkAST which ParseMetricSelector bypasses. This package matches that
// leniency.
package promqlselector
