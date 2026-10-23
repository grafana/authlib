package promqlselector

import "fmt"

// MetricNameLabel is the reserved label name used to represent the metric
// name in a matcher set. A bare metric name (e.g. `foo`) parses to a single
// matcher with Name == MetricNameLabel.
const MetricNameLabel = "__name__"

// MatchType is the operator in a label matcher.
type MatchType int

const (
	MatchEqual    MatchType = iota // =
	MatchNotEqual                  // !=
	MatchRegexp                    // =~
	MatchNotRegexp                 // !~
)

func (t MatchType) String() string {
	switch t {
	case MatchEqual:
		return "="
	case MatchNotEqual:
		return "!="
	case MatchRegexp:
		return "=~"
	case MatchNotRegexp:
		return "!~"
	}
	return fmt.Sprintf("MatchType(%d)", int(t))
}

// Matcher is a label matcher: a label name, an operator, and a value. Regex
// matchers (MatchRegexp, MatchNotRegexp) have their Value validated as a
// fully-anchored regexp at parse time but the compiled form is not retained.
type Matcher struct {
	Type  MatchType
	Name  string
	Value string
}

func (m Matcher) String() string {
	return fmt.Sprintf("%s%s%q", m.Name, m.Type, m.Value)
}
