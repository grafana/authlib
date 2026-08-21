package promqlselector

import (
	"fmt"
	"unicode/utf8"
)

type tokenType int

const (
	tkEOF tokenType = iota
	tkLBrace
	tkRBrace
	tkComma
	tkEqual
	tkNotEqual
	tkRegex
	tkNotRegex
	tkIdent
	tkString
)

func (t tokenType) String() string {
	switch t {
	case tkEOF:
		return "EOF"
	case tkLBrace:
		return "'{'"
	case tkRBrace:
		return "'}'"
	case tkComma:
		return "','"
	case tkEqual:
		return "'='"
	case tkNotEqual:
		return "'!='"
	case tkRegex:
		return "'=~'"
	case tkNotRegex:
		return "'!~'"
	case tkIdent:
		return "identifier"
	case tkString:
		return "string"
	}
	return fmt.Sprintf("token(%d)", int(t))
}

type token struct {
	typ tokenType
	// val is empty for punctuation; the identifier text for tkIdent; and the
	// *quoted* source text (including surrounding quotes) for tkString.
	val string
	pos int
}

// tokenize scans input into a token stream ending in tkEOF.
func tokenize(input string) ([]token, error) {
	toks := make([]token, 0, 8)
	i := 0
	for i < len(input) {
		c := input[i]
		if isSpace(c) {
			i++
			continue
		}
		if c == '#' {
			for i < len(input) && input[i] != '\n' {
				i++
			}
			continue
		}
		switch {
		case c == '{':
			toks = append(toks, token{typ: tkLBrace, pos: i})
			i++
		case c == '}':
			toks = append(toks, token{typ: tkRBrace, pos: i})
			i++
		case c == ',':
			toks = append(toks, token{typ: tkComma, pos: i})
			i++
		case c == '=':
			if i+1 < len(input) && input[i+1] == '~' {
				toks = append(toks, token{typ: tkRegex, pos: i})
				i += 2
			} else {
				toks = append(toks, token{typ: tkEqual, pos: i})
				i++
			}
		case c == '!':
			if i+1 < len(input) && input[i+1] == '=' {
				toks = append(toks, token{typ: tkNotEqual, pos: i})
				i += 2
			} else if i+1 < len(input) && input[i+1] == '~' {
				toks = append(toks, token{typ: tkNotRegex, pos: i})
				i += 2
			} else {
				return nil, perrAt(input, i, "expected '=' or '~' after '!'")
			}
		case isIdentStart(c):
			start := i
			for i < len(input) && isIdentContinue(input[i]) {
				i++
			}
			toks = append(toks, token{typ: tkIdent, val: input[start:i], pos: start})
		case c == '"' || c == '\'' || c == '`':
			start := i
			end, err := scanString(input, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, token{typ: tkString, val: input[start:end], pos: start})
			i = end
		default:
			return nil, perrAt(input, i, fmt.Sprintf("unexpected character %q", c))
		}
	}
	toks = append(toks, token{typ: tkEOF, pos: i})
	return toks, nil
}

func scanString(input string, i int) (int, error) {
	quote := input[i]
	start := i
	i++
	if quote == '`' {
		for i < len(input) {
			c := input[i]
			if c == '`' {
				return i + 1, nil
			}
			r, size := utf8.DecodeRuneInString(input[i:])
			if r == utf8.RuneError && size == 1 {
				return 0, perrAt(input, i, "invalid UTF-8 rune")
			}
			i += size
		}
		return 0, perrAt(input, start, "unterminated raw string")
	}
	for i < len(input) {
		c := input[i]
		if c == '\\' {
			if i+1 >= len(input) {
				return 0, perrAt(input, start, "unterminated quoted string")
			}
			i += 2
			continue
		}
		if c == '\n' {
			return 0, perrAt(input, start, "unterminated quoted string")
		}
		if c == quote {
			return i + 1, nil
		}
		r, size := utf8.DecodeRuneInString(input[i:])
		if r == utf8.RuneError && size == 1 {
			return 0, perrAt(input, i, "invalid UTF-8 rune")
		}
		i += size
	}
	return 0, perrAt(input, start, "unterminated quoted string")
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':'
}

func isIdentContinue(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// perrAt builds a ParseError with a 1-based line:col computed from offset.
func perrAt(input string, offset int, msg string) *ParseError {
	line, col := 1, 1
	end := offset
	if end > len(input) {
		end = len(input)
	}
	for i := 0; i < end; i++ {
		if input[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return &ParseError{Line: line, Col: col, Msg: msg}
}
