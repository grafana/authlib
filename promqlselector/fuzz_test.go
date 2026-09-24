package promqlselector

import (
	"errors"
	"testing"
)

var fuzzSeeds = []string{
	"",
	"foo",
	"foo:bar",
	"_foo",
	"{}",
	"{a=\"b\"}",
	"{a!=\"b\"}",
	"{a=~\"b.*\"}",
	"{a!~\"b.*\"}",
	"{a=\"b\",c=\"d\"}",
	"{a=\"b\",}",
	"foo{a=\"b\"}",
	"foo{a=\"b\",c=~\"d.*\"}",
	"{__name__=\"foo\"}",
	"{env=\"prod\"}",
	"{ a = \"b\" , c = \"d\" }",
	"{a='b'}",
	"{a=`b`}",
	"{a=\"\\n\"}",
	"{a=\"\\xFF\"}",
	"{a=\"\\u00e9\"}",
	"{a=\"\\U0001F600\"}",
	"{a=\"héllo\"}",
	"{a=\"🦀\"}",
	"foo # comment",
	"# leading\nfoo",
	"{a=\"# not a comment\"}",
	"{a=~\"foo|bar\"}",
	"{a=~\"[0-9]+\"}",
	"{a=~\"(?i)x\"}",
	"{sum=\"x\"}",
	"{by=\"x\"}",

	// Expected-reject seeds (exercise error paths without panics).
	"{env=",
	"{\"foo\"=\"bar\"}",
	"{a=}",
	"{,}",
	"foo bar",
	"foo[5m]",
	"foo offset 1m",
	"{a=\"b",
	"{a=`b",
	"{a=\"\\q\"}",
	"{a=\"\\x\"}",
	"{a=\"\\xZZ\"}",
	"{a=\"\\400\"}",
	"{a=~\"*\"}",
	"{foo:bar=\"x\"}",
	"42",
	"5m",
	"foo}",
	"{a",
	"}",
}

func FuzzParseMetricSelector(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		// Invariant: never panic; errors are well-behaved ParseError that
		// unwraps to ErrParseSelector.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %q: %v", input, r)
			}
		}()
		_, err := ParseMetricSelector(input)
		if err != nil && !errors.Is(err, ErrParseSelector) {
			t.Fatalf("error on %q does not wrap ErrParseSelector: %v", input, err)
		}
	})
}
