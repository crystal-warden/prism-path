package prismpath

import (
	"fmt"
	"strings"
	"unicode"
)

// Condition Tier Classification

var (
	alwaysSet = map[string]bool{
		"always": true, "true": true, "else": true, "otherwise": true, "default": true, "_": true,
	}
	neverSet = map[string]bool{
		"false": true, "never": true,
	}
	pyKeywords = map[string]bool{
		"as": true, "assert": true, "async": true, "await": true, "break": true,
		"class": true, "continue": true, "def": true, "del": true, "elif": true,
		"else": true, "except": true, "finally": true, "for": true, "from": true,
		"global": true, "if": true, "import": true, "is": true, "lambda": true,
		"nonlocal": true, "pass": true, "raise": true, "return": true, "try": true,
		"while": true, "with": true, "yield": true,
	}
)

// Ellipsis type sentinel representing Python's ...
type EllipsisType struct{}

var Ellipsis = EllipsisType{}

// pyTrim strips Python whitespace (including U+0085 NEL, U+001C-U+001F)
func pyTrim(text string) string {
	return strings.TrimFunc(text, func(char rune) bool {
		return unicode.IsSpace(char) || char == 0x85 || (char >= 0x1c && char <= 0x1f)
	})
}

// IsDeterministic reports whether condition is a deterministic tier edge.
func IsDeterministic(condition string) bool {
	text := strings.ToLower(pyTrim(condition))
	return strings.HasPrefix(text, "when ") || alwaysSet[text] || neverSet[text]
}

// IsError reports whether condition is an error tier edge.
func IsError(condition string) bool {
	return strings.HasPrefix(strings.ToLower(pyTrim(condition)), "on error")
}

// IsEvent reports whether condition is an event tier edge.
func IsEvent(condition string) bool {
	text := strings.ToLower(pyTrim(condition))
	return strings.HasPrefix(text, "on event") || strings.HasPrefix(text, "on timeout")
}

// EventName returns the event name for event tier edges.
func EventName(condition string) string {
	text := pyTrim(condition)
	if strings.HasPrefix(strings.ToLower(text), "on timeout") {
		return "__timeout__"
	}
	return pyTrim(text[len("on event"):])
}

// IsSemantic reports whether condition is a semantic tier edge.
func IsSemantic(condition string) bool {
	return !IsDeterministic(condition) && !IsError(condition) && !IsEvent(condition)
}

// ErrorExpr extracts the expression from an 'on error' condition.
func ErrorExpr(condition string) string {
	text := pyTrim(condition)
	return pyTrim(text[len("on error"):])
}

func exprOf(condition string) string {
	text := pyTrim(condition)
	if strings.HasPrefix(strings.ToLower(text), "when ") {
		return pyTrim(text[5:])
	}
	return text
}

// PredicateError represents an error during predicate evaluation or parsing.
type PredicateError struct {
	Message string
}

func (predErr *PredicateError) Error() string {
	return fmt.Sprintf("PredicateError: %s", predErr.Message)
}

func newPredErr(format string, args ...interface{}) error {
	return &PredicateError{Message: fmt.Sprintf(format, args...)}
}
