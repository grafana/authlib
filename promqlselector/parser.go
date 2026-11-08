package promqlselector

import (
	"fmt"
	"regexp"
	"strings"
)

// keywordsRejectedAsMetricName lists PromQL keywords that the upstream
// parser tokenizes as reserved tokens outside braces and therefore refuses
// to accept as a bare metric name, even though they're valid identifiers.
// Inside braces these same words are ordinary label names. Lookup is
// case-insensitive, mirroring upstream's strings.ToLower(word) in lex.go.
var keywordsRejectedAsMetricName = map[string]struct{}{
	"atan2":       {},
	"on":          {},
	"ignoring":    {},
	"group_left":  {},
	"group_right": {},
	"bool":        {},
	"inf":         {},
	"nan":         {},
}

// ParseMetricSelector parses input as a PromQL instant-vector selector and
// returns the list of label matchers it contains. A bare metric name is
// returned as a trailing Matcher with Name == MetricNameLabel.
func ParseMetricSelector(input string) ([]Matcher, error) {
	toks, err := tokenize(input)
	if err != nil {
		return nil, err
	}
	p := &parser{input: input, toks: toks}
	matchers, err := p.parseSelector()
	if err != nil {
		return nil, err
	}
	if p.peek().typ != tkEOF {
		return nil, p.errorAt(p.peek(), fmt.Sprintf("unexpected %s after selector", p.peek().typ))
	}
	return matchers, nil
}

type parser struct {
	input string
	toks  []token
	i     int
}

func (p *parser) peek() token {
	return p.toks[p.i]
}

func (p *parser) consume() token {
	t := p.toks[p.i]
	p.i++
	return t
}

func (p *parser) errorAt(t token, msg string) *ParseError {
	return perrAt(p.input, t.pos, msg)
}

func (p *parser) parseSelector() ([]Matcher, error) {
	var metricName string
	switch p.peek().typ {
	case tkIdent:
		nameTok := p.consume()
		if _, bad := keywordsRejectedAsMetricName[strings.ToLower(nameTok.val)]; bad {
			return nil, p.errorAt(nameTok, fmt.Sprintf("%q is reserved and cannot be a metric name", nameTok.val))
		}
		metricName = nameTok.val
	case tkLBrace:
		// no metric name
	case tkEOF:
		return nil, p.errorAt(p.peek(), "empty selector")
	default:
		return nil, p.errorAt(p.peek(), fmt.Sprintf("expected identifier or '{', got %s", p.peek().typ))
	}

	var matchers []Matcher
	if p.peek().typ == tkLBrace {
		var err error
		matchers, err = p.parseMatcherList()
		if err != nil {
			return nil, err
		}
	}

	if metricName != "" {
		matchers = append(matchers, Matcher{
			Type:  MatchEqual,
			Name:  MetricNameLabel,
			Value: metricName,
		})
	}
	return matchers, nil
}

func (p *parser) parseMatcherList() ([]Matcher, error) {
	p.consume() // '{'
	var out []Matcher
	if p.peek().typ == tkRBrace {
		p.consume()
		return out, nil
	}
	for {
		m, err := p.parseMatcher()
		if err != nil {
			return nil, err
		}
		out = append(out, m)
		switch p.peek().typ {
		case tkComma:
			p.consume()
			if p.peek().typ == tkRBrace {
				p.consume()
				return out, nil
			}
		case tkRBrace:
			p.consume()
			return out, nil
		default:
			return nil, p.errorAt(p.peek(), fmt.Sprintf("expected ',' or '}', got %s", p.peek().typ))
		}
	}
}

func (p *parser) parseMatcher() (Matcher, error) {
	nameTok := p.peek()
	if nameTok.typ != tkIdent {
		return Matcher{}, p.errorAt(nameTok, fmt.Sprintf("expected label name, got %s", nameTok.typ))
	}
	p.consume()
	if strings.ContainsRune(nameTok.val, ':') {
		return Matcher{}, p.errorAt(nameTok, "label name must not contain ':'")
	}

	opTok := p.peek()
	var mt MatchType
	switch opTok.typ {
	case tkEqual:
		mt = MatchEqual
	case tkNotEqual:
		mt = MatchNotEqual
	case tkRegex:
		mt = MatchRegexp
	case tkNotRegex:
		mt = MatchNotRegexp
	default:
		return Matcher{}, p.errorAt(opTok, fmt.Sprintf("expected matcher operator, got %s", opTok.typ))
	}
	p.consume()

	strTok := p.peek()
	if strTok.typ != tkString {
		return Matcher{}, p.errorAt(strTok, fmt.Sprintf("expected string value, got %s", strTok.typ))
	}
	p.consume()
	val, uerr := Unquote(strTok.val)
	if uerr != nil {
		return Matcher{}, p.errorAt(strTok, "invalid string literal")
	}
	if mt == MatchRegexp || mt == MatchNotRegexp {
		if _, rerr := regexp.Compile("^(?:" + val + ")$"); rerr != nil {
			return Matcher{}, p.errorAt(strTok, fmt.Sprintf("invalid regular expression: %s", rerr))
		}
	}
	return Matcher{Type: mt, Name: nameTok.val, Value: val}, nil
}
