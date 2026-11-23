package promqlselector

import (
	"errors"
	"fmt"
)

// ErrParseSelector is the sentinel returned (wrapped) for any parse failure.
// Callers can match it with errors.Is.
var ErrParseSelector = errors.New("invalid PromQL metric selector")

// ParseError carries a 1-based line and column offset pointing into the
// original input string so callers can surface useful diagnostics.
type ParseError struct {
	Line int
	Col  int
	Msg  string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%d:%d: parse error: %s", e.Line, e.Col, e.Msg)
}

func (e *ParseError) Unwrap() error {
	return ErrParseSelector
}
