package prismpath

import (
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Field definitions (SPEC section 4.5): the signed meaning of every value a flow routes on, and the checks
// of the verified core (docs/design/spec-verified-core.md). A port of prismpath/kernel/field_definitions.py
// and of the Rust twin, held to the same frozen vectors (prismpath/portable/conformance/field_definitions.json)
// and, by the differential harness (formal/diff/core_diff.py), to the Lean oracle.
//
// Parse calls applyDefinitions, which checks the policy in the core's order (section 4) and lowers every
// decimal literal compared with a fixed field to its canonical integer, exactly: decimal text is read from
// its source as a mantissa and a power of ten in math/big integers, never as a float64. A flow that breaks a
// rule comes back with FieldError set and every edge disabled, so a caller that ignores the error still
// cannot route on an unlowered threshold, and Run refuses it.

const (
	fieldPrefix        = "field."
	exactIntegerLimit  = int64(1)<<53 - 1
	maxScale           = int64(1000000000)
	maxDecimalDigits   = 28
	maxDecimalExponent = 30
	maxBrackets        = 200
)

// coreCauseCodes are the registered causes (prismpath/kernel/causes.py, append only) the core's refusals carry.
var coreCauseCodes = map[string]int{
	"route:no-matching-edge": 32, "route:contract-violation": 37,
	"image:unknown-op": 74, "image:unknown-type": 75, "image:field-index-oob": 76,
	"policy:unreadable": 89, "policy:shape": 90, "policy:not-level-m": 91, "policy:definition": 92,
	"policy:engine-counter": 93, "policy:kind-mismatch": 94, "policy:rounding": 95, "policy:threshold": 96,
	"policy:none": 97, "policy:absence-untested": 98, "reading:unreadable": 99, "reading:not-object": 100,
}

// CoreCauseCode is the registered code of one of the core's causes.
func CoreCauseCode(cause string) (int, bool) {
	code, ok := coreCauseCodes[cause]
	return code, ok
}

var engineCounters = map[string]bool{"visits": true, "error_count": true}

var definitionOptions = map[string]map[string]bool{
	"int":      {"min": true, "max": true, "absent": true},
	"fixed":    {"scale": true, "rounding": true, "unit": true, "min": true, "max": true, "absent": true},
	"bool":     {"absent": true},
	"category": {"absent": true},
}

// roundingOperators are the atoms each rounding mode carries exactly (SPEC section 4.5, rule 4); "truthy"
// stands for a bare truthiness test and "in" for membership, which only exact carries.
var roundingOperators = map[string]map[string]bool{
	"floor":   {">=": true, "<": true},
	"ceiling": {">": true, "<=": true},
	"exact":   {"<": true, "<=": true, ">": true, ">=": true, "==": true, "!=": true, "in": true, "not in": true, "truthy": true},
}

var (
	decimalTextRe = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)
	fieldNameRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	integerTextRe = regexp.MustCompile(`^[+-]?[0-9]+$`)
)

// FieldDefinition is one parsed `field.<name>` definition.
type FieldDefinition struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Scale         int64  `json:"scale,omitempty"`
	Rounding      string `json:"rounding,omitempty"`
	Unit          string `json:"unit,omitempty"`
	HasUnit       bool   `json:"-"`
	Minimum       int64  `json:"min"`
	Maximum       int64  `json:"max"`
	AbsentAllowed bool   `json:"absent_allowed"`
}

// CanonicalText is the definition written one fixed way, identical to the reference's canonical_text.
func (definition FieldDefinition) CanonicalText() string {
	words := []string{definition.Kind}
	if definition.Kind == "fixed" {
		words = append(words, fmt.Sprintf("scale=%d", definition.Scale), "rounding="+definition.Rounding)
		if definition.HasUnit {
			words = append(words, "unit="+definition.Unit)
		}
	}
	if definition.Kind == "int" || definition.Kind == "fixed" {
		words = append(words, fmt.Sprintf("min=%d", definition.Minimum), fmt.Sprintf("max=%d", definition.Maximum))
	}
	if definition.AbsentAllowed {
		words = append(words, "absent=allowed")
	} else {
		words = append(words, "absent=refused")
	}
	return strings.Join(words, " ")
}

// Problem is one way a flow breaks its field definitions: a message and the registered refusal it is,
// with Field and Reason where the refusal names them (empty otherwise).
type Problem struct {
	Cause  string
	Field  string
	Reason string
	Text   string
}

// FieldDefinitionError is a flow whose field definitions are malformed or whose conditions break a
// definition's rules. Cause is the registered refusal of the first problem in the core's order, with Field
// and Reason where it has them, Code its registered code, and Problems every problem found.
type FieldDefinitionError struct {
	Message  string
	Cause    string
	Field    string
	Reason   string
	Code     int
	Problems []Problem
}

func (fieldErr *FieldDefinitionError) Error() string { return fieldErr.Message }

// isPyWhitespace is Python's str.isspace set: U+0009 to U+000D, U+001C to U+0020, U+0085, U+00A0, U+1680,
// U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F and U+3000. It is not strings.TrimSpace's set (which lacks
// U+001C to U+001F) and not JavaScript's (which adds U+FEFF).
func isPyWhitespace(char rune) bool {
	return char == 0x85 || (char >= 0x1c && char <= 0x1f) || unicode.IsSpace(char)
}

// pySplit is Python's str.split() with no argument: the words between runs of Python whitespace.
func pySplit(text string) []string {
	return strings.FieldsFunc(text, isPyWhitespace)
}

type definitionRefusal struct {
	reason  string
	message string
}

func integerOption(name string, option string, text string) (*big.Int, *definitionRefusal) {
	if !integerTextRe.MatchString(text) {
		return nil, &definitionRefusal{"not-integer", fmt.Sprintf("field %q: %s=%q is not an integer", name, option, text)}
	}
	value, _ := new(big.Int).SetString(strings.TrimPrefix(text, "+"), 10)
	return value, nil
}

// parseDefinitionReasoned reads one `field.<name>` value as a definition, or the refusal whose reason is the
// oracle's (spec section 2.5).
func parseDefinitionReasoned(name string, text string) (FieldDefinition, *definitionRefusal) {
	none := FieldDefinition{}
	if !fieldNameRe.MatchString(name) {
		return none, &definitionRefusal{"name", fmt.Sprintf("field %q: not a field name", name)}
	}
	if engineCounters[name] {
		return none, &definitionRefusal{"engine-counter", fmt.Sprintf("field %q: the engine supplies this counter, it is not defined", name)}
	}
	words := pySplit(text)
	if len(words) == 0 {
		return none, &definitionRefusal{"empty", fmt.Sprintf("field %q: the definition is empty", name)}
	}
	kind := words[0]
	allowed, known := definitionOptions[kind]
	if !known {
		return none, &definitionRefusal{"unknown-kind", fmt.Sprintf("field %q: unknown kind %q (int, fixed, bool, category)", name, kind)}
	}
	options := map[string]string{}
	for _, word := range words[1:] {
		equals := strings.Index(word, "=")
		if equals < 0 || equals == len(word)-1 {
			return none, &definitionRefusal{"not-option", fmt.Sprintf("field %q: %q is not option=value", name, word)}
		}
		option, value := word[:equals], word[equals+1:]
		if !allowed[option] {
			return none, &definitionRefusal{"option-not-taken", fmt.Sprintf("field %q: a %s field takes no %q option", name, kind, option)}
		}
		if _, seen := options[option]; seen {
			return none, &definitionRefusal{"option-repeated", fmt.Sprintf("field %q: %q is given twice", name, option)}
		}
		options[option] = value
	}
	absent := "refused"
	if value, ok := options["absent"]; ok {
		absent = value
	}
	if absent != "refused" && absent != "allowed" {
		return none, &definitionRefusal{"absent", fmt.Sprintf("field %q: absent=%q is neither refused nor allowed", name, absent)}
	}
	definition := FieldDefinition{Name: name, Kind: kind, AbsentAllowed: absent == "allowed"}
	if kind == "fixed" {
		scaleText, hasScale := options["scale"]
		roundingText, hasRounding := options["rounding"]
		if !hasScale || !hasRounding {
			return none, &definitionRefusal{"fixed-needs-scale-and-rounding", fmt.Sprintf("field %q: a fixed field needs both scale and rounding", name)}
		}
		scaleValue, refusal := integerOption(name, "scale", scaleText)
		if refusal != nil {
			return none, refusal
		}
		if scaleValue.Cmp(big.NewInt(1)) < 0 || scaleValue.Cmp(big.NewInt(maxScale)) > 0 {
			return none, &definitionRefusal{"scale", fmt.Sprintf("field %q: scale=%s is outside 1 to %d", name, scaleValue, maxScale)}
		}
		definition.Scale = scaleValue.Int64()
		if _, ok := roundingOperators[roundingText]; !ok {
			return none, &definitionRefusal{"rounding", fmt.Sprintf("field %q: rounding=%q is not floor, ceiling or exact", name, roundingText)}
		}
		definition.Rounding = roundingText
		if unit, ok := options["unit"]; ok {
			definition.Unit, definition.HasUnit = unit, true
		}
	}
	minimum, maximum := big.NewInt(-exactIntegerLimit), big.NewInt(exactIntegerLimit)
	if text, ok := options["min"]; ok {
		value, refusal := integerOption(name, "min", text)
		if refusal != nil {
			return none, refusal
		}
		minimum = value
	}
	if text, ok := options["max"]; ok {
		value, refusal := integerOption(name, "max", text)
		if refusal != nil {
			return none, refusal
		}
		maximum = value
	}
	if minimum.Cmp(big.NewInt(-exactIntegerLimit)) < 0 || minimum.Cmp(maximum) > 0 || maximum.Cmp(big.NewInt(exactIntegerLimit)) > 0 {
		return none, &definitionRefusal{"range", fmt.Sprintf("field %q: the range %s to %s is empty or wider than plus or minus 2^53 minus 1", name, minimum, maximum)}
	}
	definition.Minimum, definition.Maximum = minimum.Int64(), maximum.Int64()
	return definition, nil
}

// ParseDefinition reads one definition from its text; the error is the refusal, its message naming the field.
func ParseDefinition(name string, text string) (FieldDefinition, error) {
	definition, refusal := parseDefinitionReasoned(name, text)
	if refusal != nil {
		return FieldDefinition{}, fmt.Errorf("%s", refusal.message)
	}
	return definition, nil
}

// ---------------------------------------------------------------------------------- exact decimals

// exactDecimal is mantissa * 10^exponent, exactly.
type exactDecimal struct {
	mantissa *big.Int
	exponent int
}

// integerLiteral is the value of an integer literal's source text (underscores removed): decimal, or a 0x, 0o or
// 0b radix literal. A decimal literal's leading zeros do not make it octal.
func integerLiteral(text string) *big.Int {
	base, digits := 10, text
	if len(text) > 2 && text[0] == '0' {
		switch text[1] {
		case 'x', 'X':
			base, digits = 16, text[2:]
		case 'o', 'O':
			base, digits = 8, text[2:]
		case 'b', 'B':
			base, digits = 2, text[2:]
		}
	}
	value, _ := new(big.Int).SetString(digits, base)
	return value
}

func negated(value exactDecimal) exactDecimal {
	return exactDecimal{mantissa: new(big.Int).Neg(value.mantissa), exponent: value.exponent}
}

// decimalValue is the exact value of decimal text within the shared bounds (at most 28 significant digits
// and an exponent of at most 30 in magnitude), or false when it is not such text.
func decimalValue(text string) (exactDecimal, bool) {
	if !decimalTextRe.MatchString(text) {
		return exactDecimal{}, false
	}
	negative := text[0] == '-'
	lower := strings.ToLower(strings.TrimLeft(text[:1], "+-") + text[1:])
	mantissaText, exponentText, hasExponent := strings.Cut(lower, "e")
	integerPart, fractionPart, _ := strings.Cut(mantissaText, ".")
	exponent := 0
	if hasExponent {
		digits := strings.TrimLeft(strings.TrimLeft(exponentText, "+-"), "0")
		if len(digits) > 3 {
			return exactDecimal{}, false
		}
		if digits != "" {
			exponent, _ = strconv.Atoi(digits)
		}
		if strings.HasPrefix(exponentText, "-") {
			exponent = -exponent
		}
		if exponent > maxDecimalExponent || exponent < -maxDecimalExponent {
			return exactDecimal{}, false
		}
	}
	significant := strings.TrimLeft(integerPart+fractionPart, "0")
	if len(significant) > maxDecimalDigits {
		return exactDecimal{}, false
	}
	magnitude := new(big.Int)
	if significant != "" {
		magnitude.SetString(significant, 10)
	}
	if negative {
		magnitude.Neg(magnitude)
	}
	return exactDecimal{mantissa: magnitude, exponent: exponent - len(fractionPart)}, true
}

func pow10(exponent int) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(exponent)), nil)
}

// settleDecimal is value * scale settled to an integer: the integer and "", or nil and the refusal reason.
// how is "floor", "ceiling" or the reason to refuse a value that is not a whole number of units.
func settleDecimal(value exactDecimal, scale int64, how string) (*big.Int, string) {
	numerator := new(big.Int).Mul(value.mantissa, big.NewInt(scale))
	if value.exponent >= 0 {
		return numerator.Mul(numerator, pow10(value.exponent)), ""
	}
	quotient, remainder := big.NewInt(0), numerator
	// past 60 digits the divisor exceeds every numerator the bounds allow (below 10^37)
	if -value.exponent <= 60 {
		quotient, remainder = new(big.Int).QuoRem(numerator, pow10(-value.exponent), new(big.Int))
	}
	switch how {
	case "floor":
		if remainder.Sign() != 0 && numerator.Sign() < 0 {
			quotient.Sub(quotient, big.NewInt(1))
		}
		return quotient, ""
	case "ceiling":
		if remainder.Sign() != 0 && numerator.Sign() > 0 {
			quotient.Add(quotient, big.NewInt(1))
		}
		return quotient, ""
	}
	if remainder.Sign() == 0 {
		return quotient, ""
	}
	return nil, how
}

func inDefinitionRange(definition FieldDefinition, canonical *big.Int) bool {
	return canonical.Cmp(big.NewInt(definition.Minimum)) >= 0 && canonical.Cmp(big.NewInt(definition.Maximum)) <= 0
}

// CanonicalValue is the canonical value of a source value under its field's definition (the reference's
// canonical_value for JSON values): the value and "", or nil and the refusal reason. A string on a numeric
// field is decimal text; a number is accepted only when integral, since the decimal a fractional double was
// printed from is lost.
func CanonicalValue(definition FieldDefinition, raw interface{}) (interface{}, string) {
	if raw == nil {
		if definition.AbsentAllowed {
			return nil, ""
		}
		return nil, "missing"
	}
	switch definition.Kind {
	case "bool":
		if _, ok := raw.(bool); ok {
			return raw, ""
		}
		return nil, "wrong_type"
	case "category":
		if _, ok := raw.(string); ok {
			return raw, ""
		}
		return nil, "wrong_type"
	}
	var exact exactDecimal
	switch typed := raw.(type) {
	case bool:
		return nil, "wrong_type"
	case int:
		exact = exactDecimal{mantissa: big.NewInt(int64(typed))}
	case int64:
		exact = exactDecimal{mantissa: big.NewInt(typed)}
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, "out_of_range"
		}
		if typed != math.Trunc(typed) {
			if definition.Kind == "fixed" {
				return nil, "binary_float"
			}
			return nil, "fractional"
		}
		mantissa, _ := new(big.Float).SetFloat64(typed).Int(nil)
		exact = exactDecimal{mantissa: mantissa}
	case string:
		parsed, ok := decimalValue(typed)
		if !ok {
			return nil, "unparseable_string"
		}
		exact = parsed
	default:
		return nil, "wrong_type"
	}
	var canonical *big.Int
	var reason string
	if definition.Kind == "fixed" {
		how := "off_grid"
		if definition.Rounding == "floor" || definition.Rounding == "ceiling" {
			how = definition.Rounding
		}
		canonical, reason = settleDecimal(exact, definition.Scale, how)
	} else {
		canonical, reason = settleDecimal(exact, 1, "fractional")
	}
	if reason != "" {
		return nil, reason
	}
	if !inDefinitionRange(definition, canonical) {
		return nil, "out_of_range"
	}
	return canonical.Int64(), ""
}

// AcceptCanonical is the refusal reason ("" when accepted) for a value that should already be canonical
// (the reference's accept_canonical). It converts nothing: a string that spells a number is the wrong
// type. A missing key or nil is the absent value, accepted only when the definition allows absence.
func AcceptCanonical(definition FieldDefinition, value interface{}) string {
	if value == nil {
		if definition.AbsentAllowed {
			return ""
		}
		return "missing"
	}
	switch definition.Kind {
	case "bool":
		if _, ok := value.(bool); ok {
			return ""
		}
		return "wrong_type"
	case "category":
		if _, ok := value.(string); ok {
			return ""
		}
		return "wrong_type"
	}
	var number int64
	switch typed := value.(type) {
	case int:
		number = int64(typed)
	case int64:
		number = typed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return "out_of_range"
		}
		if typed != math.Trunc(typed) {
			return "fractional"
		}
		if typed < float64(definition.Minimum) || typed > float64(definition.Maximum) {
			return "out_of_range"
		}
		number = int64(typed)
	default:
		return "wrong_type"
	}
	if number < definition.Minimum || number > definition.Maximum {
		return "out_of_range"
	}
	return ""
}

// ---------------------------------------------------------------------- the two checks of a reading

func firstRefused(definitions map[string]FieldDefinition, names []string, reading map[string]interface{}) (string, string, bool) {
	for _, name := range names {
		if reason := AcceptCanonical(definitions[name], reading[name]); reason != "" {
			return name, reason, true
		}
	}
	return "", "", false
}

// SystemBoundary is the first defined field, in code point order, whose value the reading does not hold
// canonically, with the reason; false when every defined field is canonical. The core's runtime boundary:
// the system's contract, every field the policy defines whether or not a rule reads it.
func SystemBoundary(graph Graph, reading map[string]interface{}) (string, string, bool) {
	names := make([]string, 0, len(graph.Fields))
	for name := range graph.Fields {
		names = append(names, name)
	}
	sort.Strings(names) // byte order of UTF-8 is code point order
	return firstRefused(graph.Fields, names, reading)
}

// PolicyCheck is the first ROUTED field, in code point order, whose value the reading does not hold
// canonically, with the reason; false when every field a rule reads is canonical. The check of a policy's
// soundness; it never produces a verdict.
func PolicyCheck(graph Graph, reading map[string]interface{}) (string, string, bool) {
	return firstRefused(graph.Fields, graph.Routed, reading)
}

// ---------------------------------------------------------------- the surface the core decodes
// The predicate language with exact literal text and spans, a sign written on a number (also outside
// parentheses, as Python's syntax tree holds `-(5)`), and a grouping parenthesis transparent. It follows the
// Rust tokenizer rule for rule, so it reads exactly what the other kernels read, but keeps what evaluation
// discards: a number's source text and its span.

type surfaceToken struct {
	kind  string // name, num, str, ellipsis, op
	text  string // a name, a string's value, an operator, or a number's source
	float bool
	start int
	end   int
}

type surfaceFailure struct{}

func surfaceFail() { panic(surfaceFailure{}) }

func isASCIIAlpha(char rune) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z')
}
func isASCIIHex(char rune) bool {
	return isDigitRune(char) || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')
}

// tokenizeSurface is the token list of an expression, each token with its span in runes, or false when the
// expression is not tokenizable. The tokenizer's own whitespace is exactly " \t\n\r".
func tokenizeSurface(src []rune) ([]surfaceToken, bool) {
	var toks []surfaceToken
	length := len(src)
	pos := 0
	at := func(index int) rune {
		if index < length {
			return src[index]
		}
		return -1
	}
	for pos < length {
		char := src[pos]
		if char == ' ' || char == '\t' || char == '\n' || char == '\r' {
			pos++
			continue
		}
		start := pos
		switch {
		case isASCIIAlpha(char) || char == '_':
			if (char == 'r' || char == 'R') && (at(pos+1) == '\'' || at(pos+1) == '"') {
				quote := src[pos+1]
				scan := pos + 2
				for scan < length && src[scan] != quote {
					scan++
				}
				if scan >= length {
					return nil, false
				}
				toks = append(toks, surfaceToken{kind: "str", text: string(src[pos+2 : scan]), start: start, end: scan + 1})
				pos = scan + 1
				continue
			}
			if (char == 'b' || char == 'B') && (at(pos+1) == '\'' || at(pos+1) == '"') {
				return nil, false
			}
			scan := pos + 1
			for scan < length && (isASCIIAlpha(src[scan]) || isDigitRune(src[scan]) || src[scan] == '_') {
				scan++
			}
			toks = append(toks, surfaceToken{kind: "name", text: string(src[pos:scan]), start: start, end: scan})
			pos = scan
		case isDigitRune(char) || (char == '.' && isDigitRune(at(pos+1))):
			radixWord := strings.ToLower(string(src[pos:min(pos+2, length)]))
			if char == '0' && (radixWord == "0x" || radixWord == "0o" || radixWord == "0b") {
				scan := pos + 2
				for scan < length {
					digit := src[scan]
					ok := digit == '_'
					switch radixWord {
					case "0x":
						ok = ok || isASCIIHex(digit)
					case "0o":
						ok = ok || (digit >= '0' && digit <= '7')
					default:
						ok = ok || digit == '0' || digit == '1'
					}
					if !ok {
						break
					}
					scan++
				}
				if strings.ReplaceAll(string(src[pos+2:scan]), "_", "") == "" {
					return nil, false
				}
				toks = append(toks, surfaceToken{kind: "num", text: string(src[pos:scan]), start: start, end: scan})
				pos = scan
				continue
			}
			scan := pos
			for scan < length && (isDigitRune(src[scan]) || src[scan] == '_') {
				scan++
			}
			if scan < length && src[scan] == '.' {
				scan++
				for scan < length && (isDigitRune(src[scan]) || src[scan] == '_') {
					scan++
				}
			}
			if scan < length && (src[scan] == 'e' || src[scan] == 'E') {
				expScan := scan + 1
				if expScan < length && (src[expScan] == '+' || src[expScan] == '-') {
					expScan++
				}
				if expScan < length && isDigitRune(src[expScan]) {
					expScan++
					for expScan < length && (isDigitRune(src[expScan]) || src[expScan] == '_') {
						expScan++
					}
					scan = expScan
				}
			}
			if scan < length && (src[scan] == 'j' || src[scan] == 'J') {
				return nil, false
			}
			text := string(src[pos:scan])
			toks = append(toks, surfaceToken{kind: "num", text: text, float: strings.ContainsAny(text, ".eE"), start: start, end: scan})
			pos = scan
		case char == '"' || char == '\'':
			scan := pos + 1
			var out []rune
			for scan < length && src[scan] != char {
				if src[scan] == '\\' && scan+1 < length {
					esc := src[scan+1]
					switch {
					case esc == 'n':
						out = append(out, '\n')
					case esc == 't':
						out = append(out, '\t')
					case esc == 'r':
						out = append(out, '\r')
					case esc == '0':
						out = append(out, 0)
					case esc == 'a':
						out = append(out, 7)
					case esc == 'b':
						out = append(out, 8)
					case esc == 'f':
						out = append(out, 12)
					case esc == 'v':
						out = append(out, 11)
					case esc == '\\' || esc == '\'' || esc == '"':
						out = append(out, esc)
					case esc == 'x' && scan+3 < length && isASCIIHex(src[scan+2]) && isASCIIHex(src[scan+3]):
						code, _ := strconv.ParseInt(string(src[scan+2:scan+4]), 16, 32)
						out = append(out, rune(code))
						scan += 2
					case esc == 'u' && scan+5 < length && isASCIIHex(src[scan+2]) && isASCIIHex(src[scan+3]) && isASCIIHex(src[scan+4]) && isASCIIHex(src[scan+5]):
						code, _ := strconv.ParseInt(string(src[scan+2:scan+6]), 16, 32)
						if code >= 0xd800 && code <= 0xdfff {
							code = 0xfffd
						}
						out = append(out, rune(code))
						scan += 4
					default:
						out = append(out, '\\', esc)
					}
					scan += 2
				} else {
					out = append(out, src[scan])
					scan++
				}
			}
			if scan >= length {
				return nil, false
			}
			toks = append(toks, surfaceToken{kind: "str", text: string(out), start: start, end: scan + 1})
			pos = scan + 1
		case char == '.' && at(pos+1) == '.' && at(pos+2) == '.':
			toks = append(toks, surfaceToken{kind: "ellipsis", start: start, end: pos + 3})
			pos += 3
		case (char == '=' || char == '!' || char == '<' || char == '>') && at(pos+1) == '=':
			toks = append(toks, surfaceToken{kind: "op", text: string(src[pos : pos+2]), start: start, end: pos + 2})
			pos += 2
		case strings.ContainsRune("<>[](),-+", char):
			toks = append(toks, surfaceToken{kind: "op", text: string(char), start: start, end: pos + 1})
			pos++
		default:
			return nil, false
		}
	}
	return toks, true
}

// surfaceNode is one node of the surface tree.
type surfaceNode struct {
	kind      string // name, num, str, bool, null, ellipsis, list, cmp, and, or, not
	text      string // a name, a string's value, or a number's source without underscores
	boolean   bool
	elements  []*surfaceNode // list elements, and/or operands, a comparison's operands, a not's operand
	ops       []string
	float     bool
	negative  bool
	radix     bool
	separated bool
	start     int
	end       int
}

type surfaceParser struct {
	src      []rune
	toks     []surfaceToken
	pos      int
	brackets int
}

func (parser *surfaceParser) peek() *surfaceToken {
	if parser.pos < len(parser.toks) {
		return &parser.toks[parser.pos]
	}
	return nil
}

func (parser *surfaceParser) peekOp(op string) bool {
	tok := parser.peek()
	return tok != nil && tok.kind == "op" && tok.text == op
}

func (parser *surfaceParser) peekName(name string) bool {
	tok := parser.peek()
	return tok != nil && tok.kind == "name" && tok.text == name
}

func (parser *surfaceParser) expect(op string) {
	if !parser.peekOp(op) {
		surfaceFail()
	}
	parser.pos++
}

func (parser *surfaceParser) joined(keyword string, next func() *surfaceNode) *surfaceNode {
	values := []*surfaceNode{next()}
	for parser.peekName(keyword) {
		parser.pos++
		values = append(values, next())
	}
	if len(values) == 1 {
		return values[0]
	}
	return &surfaceNode{kind: keyword, elements: values}
}

func (parser *surfaceParser) orExpr() *surfaceNode  { return parser.joined("or", parser.andExpr) }
func (parser *surfaceParser) andExpr() *surfaceNode { return parser.joined("and", parser.notExpr) }

func (parser *surfaceParser) notExpr() *surfaceNode {
	if parser.peekName("not") {
		parser.pos++
		return &surfaceNode{kind: "not", elements: []*surfaceNode{parser.notExpr()}}
	}
	return parser.compare()
}

func (parser *surfaceParser) compareOp() string {
	tok := parser.peek()
	if tok == nil {
		return ""
	}
	switch {
	case tok.kind == "op" && (tok.text == "==" || tok.text == "!=" || tok.text == "<" || tok.text == "<=" || tok.text == ">" || tok.text == ">="):
		parser.pos++
		return tok.text
	case tok.kind == "name" && tok.text == "in":
		parser.pos++
		return "in"
	case tok.kind == "name" && tok.text == "not":
		parser.pos++
		if !parser.peekName("in") {
			surfaceFail()
		}
		parser.pos++
		return "not in"
	}
	return ""
}

func (parser *surfaceParser) compare() *surfaceNode {
	operands := []*surfaceNode{parser.operand()}
	var ops []string
	for op := parser.compareOp(); op != ""; op = parser.compareOp() {
		ops = append(ops, op)
		operands = append(operands, parser.operand())
	}
	if len(ops) == 0 {
		return operands[0]
	}
	return &surfaceNode{kind: "cmp", elements: operands, ops: ops}
}

func (parser *surfaceParser) open() {
	// Python's tokenizer refuses more than 200 open brackets
	if parser.brackets >= maxBrackets {
		surfaceFail()
	}
	parser.brackets++
}

func (parser *surfaceParser) number(index int, negative bool, start int, end int, separated bool) *surfaceNode {
	tok := parser.toks[index]
	text := strings.ReplaceAll(tok.text, "_", "")
	lower := strings.ToLower(text)
	radix := strings.HasPrefix(lower, "0x") || strings.HasPrefix(lower, "0o") || strings.HasPrefix(lower, "0b")
	return &surfaceNode{kind: "num", text: text, float: tok.float, negative: negative, radix: radix, start: start, end: end, separated: separated}
}

func (parser *surfaceParser) sequence(closer string) []*surfaceNode {
	var elements []*surfaceNode
	if parser.peek() != nil && !parser.peekOp(closer) {
		elements = append(elements, parser.orExpr())
		for parser.peekOp(",") {
			parser.pos++
			if parser.peekOp(closer) {
				break
			}
			elements = append(elements, parser.orExpr())
		}
	}
	parser.expect(closer)
	return elements
}

func (parser *surfaceParser) operand() *surfaceNode {
	tok := parser.peek()
	if tok == nil {
		surfaceFail()
	}
	parser.pos++
	switch tok.kind {
	case "op":
		switch tok.text {
		case "-", "+":
			negative := tok.text == "-"
			if next := parser.peek(); next != nil && next.kind == "num" {
				parser.pos++
				return parser.number(parser.pos-1, negative, tok.start, next.end, false)
			}
			// `-(5)`: one number in parentheses, a signed literal in Python's syntax tree
			if parser.peekOp("(") && parser.pos+2 < len(parser.toks) && parser.toks[parser.pos+1].kind == "num" &&
				parser.toks[parser.pos+2].kind == "op" && parser.toks[parser.pos+2].text == ")" {
				close := parser.toks[parser.pos+2]
				parser.pos += 3
				return parser.number(parser.pos-2, negative, tok.start, close.end, true)
			}
			surfaceFail()
		case "[":
			parser.open()
			elements := parser.sequence("]")
			parser.brackets--
			return &surfaceNode{kind: "list", elements: elements}
		case "(":
			if parser.peekOp(")") {
				parser.pos++
				return &surfaceNode{kind: "list"}
			}
			parser.open()
			first := parser.orExpr()
			if parser.peekOp(",") {
				elements := []*surfaceNode{first}
				for parser.peekOp(",") {
					parser.pos++
					if parser.peekOp(")") {
						break
					}
					elements = append(elements, parser.orExpr())
				}
				parser.expect(")")
				parser.brackets--
				return &surfaceNode{kind: "list", elements: elements}
			}
			parser.expect(")")
			parser.brackets--
			return first
		}
		surfaceFail()
	case "num":
		return parser.number(parser.pos-1, false, tok.start, tok.end, false)
	case "str":
		return &surfaceNode{kind: "str", text: tok.text}
	case "ellipsis":
		return &surfaceNode{kind: "ellipsis"}
	case "name":
		switch tok.text {
		case "True":
			return &surfaceNode{kind: "bool", boolean: true}
		case "False":
			return &surfaceNode{kind: "bool"}
		case "None":
			return &surfaceNode{kind: "null"}
		case "and", "or", "not", "in":
			surfaceFail()
		}
		if pyKeywords[tok.text] {
			surfaceFail()
		}
		return &surfaceNode{kind: "name", text: tok.text}
	}
	surfaceFail()
	return nil
}

// parseSurface is the surface tree of an expression, or nil when it is not in the predicate language. A top
// level tuple, `x, y`, is no condition of the predicate language, but the lowering of an error edge still
// walks one, so allowTuple reads it as an `and`.
func parseSurface(expr string, allowTuple bool) (tree *surfaceNode) {
	src := []rune(expr)
	toks, ok := tokenizeSurface(src)
	if !ok {
		return nil
	}
	parser := &surfaceParser{src: src, toks: toks}
	defer func() {
		if recovered := recover(); recovered != nil {
			if _, isFailure := recovered.(surfaceFailure); !isFailure {
				panic(recovered)
			}
			tree = nil
		}
	}()
	tree = parser.orExpr()
	if allowTuple && parser.peekOp(",") {
		elements := []*surfaceNode{tree}
		for parser.peekOp(",") {
			parser.pos++
			if parser.peek() == nil {
				break
			}
			elements = append(elements, parser.orExpr())
		}
		tree = &surfaceNode{kind: "and", elements: elements}
	}
	if parser.pos != len(toks) {
		return nil
	}
	return tree
}

// desugarSurface turns `a < b < c` into `a < b and b < c`, recursively: the one desugaring (the
// reference's _desugar_chains).
func desugarSurface(node *surfaceNode) *surfaceNode {
	switch node.kind {
	case "and", "or", "not":
		elements := make([]*surfaceNode, len(node.elements))
		for index, element := range node.elements {
			elements[index] = desugarSurface(element)
		}
		return &surfaceNode{kind: node.kind, elements: elements}
	case "cmp":
		if len(node.ops) > 1 {
			links := make([]*surfaceNode, len(node.ops))
			for index, op := range node.ops {
				links[index] = &surfaceNode{kind: "cmp", elements: []*surfaceNode{node.elements[index], node.elements[index+1]}, ops: []string{op}}
			}
			return &surfaceNode{kind: "and", elements: links}
		}
	}
	return node
}

// -------------------------------------------------------------------- decoding to the core's syntax

// coreConst is a constant of the core (spec section 2.3): kind "int", "dec", "bool", "str" or "none".
type coreConst struct {
	kind    string
	integer *big.Int
	text    string // a decimal's source, or a string's value
	exact   exactDecimal
	boolean bool
}

// coreCond is a condition of the core's abstract syntax (spec section 2.2): kind "always", "never",
// "truthy", "cmp", "mem", "not", "and" or "or".
type coreCond struct {
	kind     string
	field    string
	op       string
	constant coreConst
	members  []coreConst
	children []*coreCond
}

type refusedPanic struct{ problem Problem }

func problemOf(cause string, text string, field string, reason string) Problem {
	return Problem{Cause: cause, Field: field, Reason: reason, Text: text}
}

func outsideLevelM(where string, cond string, cause string, reason string) refusedPanic {
	return refusedPanic{problemOf(cause, fmt.Sprintf("%s: %q is outside Level M (%s), and a flow that defines its fields routes only on Level M conditions", where, cond, reason), "", reason)}
}

var flipOperator = map[string]string{"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}

func decodeConst(node *surfaceNode, where string, cond string) coreConst {
	switch node.kind {
	case "num":
		if !node.float {
			magnitude := integerLiteral(node.text)
			if node.negative {
				magnitude.Neg(magnitude)
			}
			return coreConst{kind: "int", integer: magnitude}
		}
		exact, ok := decimalValue(node.text)
		if !ok {
			panic(refusedPanic{problemOf("policy:threshold", fmt.Sprintf("%s: %q: the literal %q has more digits than an exact threshold carries", where, cond, node.text), "", "digits")})
		}
		text := node.text
		if node.negative {
			text, exact = "-"+text, negated(exact)
		}
		return coreConst{kind: "dec", text: text, exact: exact}
	case "str":
		return coreConst{kind: "str", text: node.text}
	case "bool":
		return coreConst{kind: "bool", boolean: node.boolean}
	case "null":
		return coreConst{kind: "none"}
	case "name":
		panic(outsideLevelM(where, cond, "image:unknown-type", "field-vs-field"))
	case "list":
		panic(outsideLevelM(where, cond, "image:unknown-type", "nested-container"))
	}
	panic(outsideLevelM(where, cond, "image:unknown-type", "constant"))
}

func decodeSurface(node *surfaceNode, where string, cond string) *coreCond {
	switch node.kind {
	case "and", "or":
		children := make([]*coreCond, len(node.elements))
		for index, element := range node.elements {
			children[index] = decodeSurface(element, where, cond)
		}
		return &coreCond{kind: node.kind, children: children}
	case "not":
		return &coreCond{kind: "not", children: []*coreCond{decodeSurface(node.elements[0], where, cond)}}
	case "name":
		return &coreCond{kind: "truthy", field: node.text}
	case "cmp":
		if len(node.ops) != 1 {
			panic(outsideLevelM(where, cond, "policy:not-level-m", "disallowed-or-unparseable"))
		}
		left, right, op := node.elements[0], node.elements[1], node.ops[0]
		if op == "in" || op == "not in" {
			if left.kind != "name" {
				panic(outsideLevelM(where, cond, "policy:not-level-m", "name"))
			}
			if right.kind != "list" {
				panic(outsideLevelM(where, cond, "image:unknown-op", "membership-not-in-a-list"))
			}
			members := make([]coreConst, len(right.elements))
			for index, element := range right.elements {
				members[index] = decodeConst(element, where, cond)
			}
			return &coreCond{kind: "mem", field: left.text, op: op, members: members}
		}
		var field string
		var constantNode *surfaceNode
		oriented := op
		switch {
		case left.kind == "name":
			field, constantNode = left.text, right
		case right.kind == "name":
			field, constantNode, oriented = right.text, left, flipOperator[op]
		default:
			panic(outsideLevelM(where, cond, "policy:not-level-m", "name"))
		}
		constant := decodeConst(constantNode, where, cond)
		if (oriented == "<" || oriented == "<=" || oriented == ">" || oriented == ">=") && constant.kind == "str" {
			panic(outsideLevelM(where, cond, "image:unknown-op", "string-ordering"))
		}
		return &coreCond{kind: "cmp", field: field, op: oriented, constant: constant}
	case "bool", "null", "num", "str", "ellipsis":
		panic(outsideLevelM(where, cond, "policy:not-level-m", "name"))
	}
	panic(outsideLevelM(where, cond, "policy:not-level-m", "disallowed-or-unparseable"))
}

// coreDepth is the core's depth of a decoded condition (spec section 2.4, Lean Cond.depth).
func coreDepth(cond *coreCond) int {
	switch cond.kind {
	case "always", "never":
		return 0
	case "truthy":
		return 1
	case "cmp", "mem":
		return 2
	case "not":
		return 1 + coreDepth(cond.children[0])
	}
	deepest := 0
	for _, child := range cond.children {
		deepest = max(deepest, coreDepth(child))
	}
	return 1 + deepest
}

// decodeCondition reads one deterministic condition in the core's abstract syntax, or the problem that
// refuses it at decoding (phase 1 of spec section 4), as the reference's decode_condition.
func decodeCondition(cond string, where string) (decoded *coreCond, found *Problem) {
	expr := exprOf(cond)
	lower := strings.ToLower(expr)
	if alwaysSet[lower] {
		return &coreCond{kind: "always"}, nil
	}
	if neverSet[lower] {
		return &coreCond{kind: "never"}, nil
	}
	tree := parseSurface(expr, false)
	if tree == nil {
		refused := problemOf("policy:not-level-m", fmt.Sprintf("%s: %q does not parse in the predicate language, and a flow that defines its fields routes only on Level M conditions", where, cond), "", "disallowed-or-unparseable")
		return nil, &refused
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			refused, ok := recovered.(refusedPanic)
			if !ok {
				panic(recovered)
			}
			decoded, found = nil, &refused.problem
		}
	}()
	decoded = decodeSurface(desugarSurface(tree), where, cond)
	// SPEC section 4.1, by the core's measure (spec section 2.4)
	if coreDepth(decoded) > maxPredicateDepth {
		refused := problemOf("policy:not-level-m", fmt.Sprintf("%s: %q is nested too deeply (> %d)", where, cond, maxPredicateDepth), "", "depth")
		return nil, &refused
	}
	return decoded, nil
}

// ------------------------------------------------------------------ the checks of one atom (rules 2-5)

// roundingCarries is whether a rounding mode carries an operator (rule 4); "truthy" stands for truthiness
// and membership.
func roundingCarries(rounding string, op string) bool {
	return roundingOperators[rounding][op]
}

func roundingProblem(definition FieldDefinition, op string) *Problem {
	allowed := make([]string, 0)
	for operator := range roundingOperators[definition.Rounding] {
		allowed = append(allowed, operator)
	}
	sort.Strings(allowed)
	written := "a bare truthiness test or a membership"
	if op != "truthy" {
		written = strconv.Quote(op)
	}
	found := problemOf("policy:rounding", fmt.Sprintf("field %q: rounding=%s carries only %s, so %s would not decide on the canonical value as it does on the source value", definition.Name, definition.Rounding, strings.Join(allowed, " and "), written), definition.Name, "")
	return &found
}

func thresholdProblem(definition FieldDefinition, text string, reason string) *Problem {
	found := problemOf("policy:threshold", fmt.Sprintf("field %q: the threshold %s is %s for %q", definition.Name, text, strings.ReplaceAll(reason, "-", " "), definition.CanonicalText()), definition.Name, reason)
	return &found
}

// lowerNumber checks a numeric constant of an int or fixed field against the field (Lean lowerNum).
func lowerNumber(definition FieldDefinition, constant coreConst) *Problem {
	fixed := definition.Kind == "fixed"
	switch constant.kind {
	case "int":
		value := constant.integer
		if fixed {
			value = new(big.Int).Mul(value, big.NewInt(definition.Scale))
		}
		if inDefinitionRange(definition, value) {
			return nil
		}
		reason := "constant-range"
		if fixed {
			reason = "out-of-range"
		}
		return thresholdProblem(definition, constant.integer.String(), reason)
	case "dec":
		if !fixed {
			found := problemOf("image:unknown-type", fmt.Sprintf("field %q: the decimal %s is a float, and a %s field compares integers", definition.Name, constant.text, definition.Kind), "", "float")
			return &found
		}
		scaled, reason := settleDecimal(constant.exact, definition.Scale, "off-grid")
		if reason != "" {
			return thresholdProblem(definition, constant.text, "off-grid")
		}
		if inDefinitionRange(definition, scaled) {
			return nil
		}
		return thresholdProblem(definition, constant.text, "out-of-range")
	}
	found := problemOf("policy:kind-mismatch", fmt.Sprintf("field %q: a %s field is compared only with numbers", definition.Name, definition.Kind), definition.Name, "")
	return &found
}

func floatProblem(definition FieldDefinition, text string) *Problem {
	found := problemOf("image:unknown-type", fmt.Sprintf("field %q: the decimal %s is a float, and a %s field takes none", definition.Name, text, definition.Kind), "", "float")
	return &found
}

// atomProblem is why one decoded atom breaks its field's definition, or nil (Lean checkTruthy, checkCmp,
// checkMem, in their order; the reference's _atom_problem).
func atomProblem(definition FieldDefinition, atom *coreCond) *Problem {
	name, kind := definition.Name, definition.Kind
	fixed := kind == "fixed"
	switch atom.kind {
	case "truthy":
		if fixed && !roundingCarries(definition.Rounding, "truthy") {
			return roundingProblem(definition, "truthy")
		}
		return nil
	case "cmp":
		op, constant := atom.op, atom.constant
		if constant.kind == "none" {
			if op != "==" && op != "!=" {
				found := problemOf("policy:none", fmt.Sprintf("field %q: None is compared only by == or !=", name), name, "ordered")
				return &found
			}
			if !definition.AbsentAllowed {
				found := problemOf("policy:none", fmt.Sprintf("field %q: compared with None, but its definition refuses absence", name), name, "absence-refused")
				return &found
			}
			return nil
		}
		if kind == "bool" || kind == "category" {
			own := "str"
			if kind == "bool" {
				own = "bool"
			}
			if constant.kind == own && (op == "==" || op == "!=") {
				return nil
			}
			if constant.kind == "dec" {
				return floatProblem(definition, constant.text)
			}
			text := fmt.Sprintf("field %q: a category field is compared with strings by ==, !=, in and not in", name)
			if kind == "bool" {
				text = fmt.Sprintf("field %q: a bool field is tested by truthiness or == and != with True or False", name)
			}
			found := problemOf("policy:kind-mismatch", text, name, "")
			return &found
		}
		isNumber := constant.kind == "int" || constant.kind == "dec"
		if fixed && !roundingCarries(definition.Rounding, op) && isNumber {
			return roundingProblem(definition, op)
		}
		if found := lowerNumber(definition, constant); found != nil {
			return found
		}
		if fixed && !roundingCarries(definition.Rounding, op) {
			return roundingProblem(definition, op)
		}
		return nil
	}
	for _, member := range atom.members {
		if member.kind == "none" {
			found := problemOf("policy:none", fmt.Sprintf("field %q: None may not appear in a list", name), name, "in-list")
			return &found
		}
	}
	for _, member := range atom.members {
		if kind == "category" && member.kind == "str" {
			continue
		}
		if kind == "int" || kind == "fixed" {
			if found := lowerNumber(definition, member); found != nil {
				return found
			}
			continue
		}
		if member.kind == "dec" {
			return floatProblem(definition, member.text)
		}
		with := "True or False"
		if kind == "category" {
			with = "strings"
		}
		found := problemOf("policy:kind-mismatch", fmt.Sprintf("field %q: a %s field is compared with %s only", name, kind, with), name, "")
		return &found
	}
	if fixed && !roundingCarries(definition.Rounding, "truthy") {
		return roundingProblem(definition, "truthy")
	}
	return nil
}

// coreAtoms are the atoms of a decoded condition, depth first and left to right.
func coreAtoms(cond *coreCond, out []*coreCond) []*coreCond {
	switch cond.kind {
	case "always", "never":
	case "not", "and", "or":
		for _, child := range cond.children {
			out = coreAtoms(child, out)
		}
	default:
		out = append(out, cond)
	}
	return out
}

type coreRule struct {
	where   string
	cond    string
	decoded *coreCond
}

// coreRules are the deterministic edges of the flow, in node order and edge order: the rules of the core.
func coreRules(graph Graph) [][2]string {
	var rules [][2]string
	for _, name := range graph.NodeOrder {
		node, ok := graph.Nodes[name]
		if !ok {
			continue
		}
		for _, edge := range node.Edges {
			if IsDeterministic(edge.Condition) && !IsSemantic(edge.Condition) {
				rules = append(rules, [2]string{name, edge.Condition})
			}
		}
	}
	return rules
}

// coreAnalysis lists every problem of a flow that defines its fields, in the order of spec section 4, with
// the decoded rules: the first problem is the one the core refuses the policy for, the rest are diagnostics.
// The twin of the reference's core_problems. Phase 1 decodes rule by rule, phase 2 parses the definitions in
// code point order, phase 3 checks every atom against its definition, phase 4 is rule 6.
func coreAnalysis(graph Graph, meta map[string]string) (problems []Problem, rules []coreRule, definitions map[string]FieldDefinition) {
	texts := map[string]string{}
	for key, value := range meta {
		if strings.HasPrefix(key, fieldPrefix) {
			texts[key[len(fieldPrefix):]] = value
		}
	}
	names := make([]string, 0, len(texts))
	for name := range texts {
		names = append(names, name)
	}
	sort.Strings(names) // byte order of UTF-8 is code point order
	for _, rule := range coreRules(graph) {
		decoded, found := decodeCondition(rule[1], rule[0])
		if found != nil {
			problems = append(problems, *found)
		} else {
			rules = append(rules, coreRule{where: rule[0], cond: rule[1], decoded: decoded})
		}
	}
	definitions = map[string]FieldDefinition{}
	for _, name := range names {
		definition, refusal := parseDefinitionReasoned(name, texts[name])
		if refusal != nil {
			problems = append(problems, problemOf("policy:definition", refusal.message, name, refusal.reason))
			continue
		}
		definitions[name] = definition
	}
	testedForAbsence := map[string]bool{}
	for _, rule := range rules {
		for _, atom := range coreAtoms(rule.decoded, nil) {
			// the engine's registers are outside the core (spec section 1), routed by the flow engine
			if engineCounters[atom.field] {
				continue
			}
			definition, defined := definitions[atom.field]
			if !defined {
				if _, written := texts[atom.field]; !written {
					problems = append(problems, problemOf("image:field-index-oob", fmt.Sprintf("%s: %q reads %q, which the flow does not define", rule.where, rule.cond, atom.field), atom.field, ""))
				}
				continue
			}
			if found := atomProblem(definition, atom); found != nil {
				found.Text = fmt.Sprintf("%s: %q: %s", rule.where, rule.cond, found.Text)
				problems = append(problems, *found)
			} else if atom.kind == "cmp" && atom.constant.kind == "none" {
				testedForAbsence[atom.field] = true
			}
		}
	}
	for _, name := range names {
		if definition, defined := definitions[name]; defined && definition.AbsentAllowed && !testedForAbsence[name] {
			problems = append(problems, problemOf("policy:absence-untested", fmt.Sprintf("field %q allows absence but no edge tests it with == None or != None, so absence would only ever be observed by accident", name), name, ""))
		}
	}
	return problems, rules, definitions
}

// ------------------------------------------------------------------------------------- lowering

// lowerExpression is the expression with every numeric literal compared with a fixed field replaced by its
// canonical integer, rewritten in place by the literal's span in the source. A literal outside the core's
// syntax (a sign written outside parentheses, a literal between two fixed fields of different scales) or
// off its field's grid is a panic carrying a refusedPanic; an expression that does not parse comes back
// unchanged, and the policy rules report it.
func lowerExpression(expr string, definitions map[string]FieldDefinition) string {
	fixed := map[string]bool{}
	for name, definition := range definitions {
		if definition.Kind == "fixed" {
			fixed[name] = true
		}
	}
	if len(fixed) == 0 {
		return expr
	}
	tree := parseSurface(expr, true)
	if tree == nil {
		return expr
	}
	src := []rune(expr)
	type replacement struct {
		field     string
		canonical *big.Int
		start     int
		end       int
	}
	replacements := map[[2]int]replacement{}
	lowerOne := func(field string, node *surfaceNode) {
		if node.kind != "num" {
			return
		}
		source := string(src[node.start:node.end])
		if node.separated {
			panic(refusedPanic{problemOf("policy:threshold", fmt.Sprintf("the threshold %s puts its sign outside parentheses; write the sign on the number", source), "", "sign")})
		}
		definition := definitions[field]
		var exact exactDecimal
		if node.radix || !node.float {
			magnitude := integerLiteral(node.text)
			if node.negative {
				magnitude.Neg(magnitude)
			}
			exact = exactDecimal{mantissa: magnitude}
		} else {
			parsed, ok := decimalValue(node.text)
			if !ok {
				panic(refusedPanic{problemOf("policy:threshold", fmt.Sprintf("the literal %q has more digits than an exact threshold carries", node.text), "", "digits")})
			}
			exact = parsed
			if node.negative {
				exact = negated(exact)
			}
		}
		canonical, reason := settleDecimal(exact, definition.Scale, "off-grid")
		if reason != "" {
			panic(refusedPanic{problemOf("policy:threshold", fmt.Sprintf("field %q: the threshold %s is not a multiple of 1/%d", field, source, definition.Scale), field, "off-grid")})
		}
		if !inDefinitionRange(definition, canonical) {
			panic(refusedPanic{problemOf("policy:threshold", fmt.Sprintf("field %q: the threshold %s is %s canonically, outside %d to %d", field, source, canonical, definition.Minimum, definition.Maximum), field, "out-of-range")})
		}
		span := [2]int{node.start, node.end}
		if previous, seen := replacements[span]; seen && previous.field != field && definitions[previous.field].Scale != definition.Scale {
			panic(refusedPanic{problemOf("policy:threshold", fmt.Sprintf("the literal %s sits between two fixed fields of different scales", source), "", "two-scales")})
		}
		replacements[span] = replacement{field: field, canonical: canonical, start: node.start, end: node.end}
	}
	fixedName := func(node *surfaceNode) string {
		if node.kind == "name" && fixed[node.text] {
			return node.text
		}
		return ""
	}
	var walk func(node *surfaceNode)
	walk = func(node *surfaceNode) {
		switch node.kind {
		case "cmp":
			for index, op := range node.ops {
				left, right := node.elements[index], node.elements[index+1]
				if op == "in" || op == "not in" {
					if field := fixedName(left); field != "" && right.kind == "list" {
						for _, element := range right.elements {
							lowerOne(field, element)
						}
					}
					continue
				}
				if field := fixedName(left); field != "" {
					lowerOne(field, right)
				}
				if field := fixedName(right); field != "" {
					lowerOne(field, left)
				}
			}
			for _, operand := range node.elements {
				walk(operand)
			}
		case "and", "or", "not", "list":
			for _, child := range node.elements {
				walk(child)
			}
		}
	}
	walk(tree)
	ordered := make([]replacement, 0, len(replacements))
	for _, found := range replacements {
		ordered = append(ordered, found)
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].start > ordered[right].start })
	for _, found := range ordered {
		src = append(append(append([]rune{}, src[:found.start]...), []rune(found.canonical.String())...), src[found.end:]...)
	}
	return string(src)
}

// lowerCondition is a `when` or `on error when` condition with its expression lowered; any other condition
// as is.
func lowerCondition(cond string, definitions map[string]FieldDefinition) string {
	var expr string
	switch {
	case IsDeterministic(cond):
		expr = exprOf(cond)
	case IsError(cond) && strings.HasPrefix(strings.ToLower(ErrorExpr(cond)), "when "):
		expr = exprOf(ErrorExpr(cond))
	default:
		return cond
	}
	lower := strings.ToLower(expr)
	if alwaysSet[lower] || neverSet[lower] {
		return cond
	}
	stripped := strings.TrimRightFunc(cond, isPyWhitespace)
	if !strings.HasSuffix(stripped, expr) {
		return cond
	}
	return stripped[:len(stripped)-len(expr)] + lowerExpression(expr, definitions)
}

// lowerConditionChecked lowers a condition and returns the problem a literal outside the core's syntax is.
func lowerConditionChecked(cond string, definitions map[string]FieldDefinition) (lowered string, found *Problem) {
	defer func() {
		if recovered := recover(); recovered != nil {
			refused, ok := recovered.(refusedPanic)
			if !ok {
				panic(recovered)
			}
			lowered, found = cond, &refused.problem
		}
	}()
	return lowerCondition(cond, definitions), nil
}

// applyDefinitions checks the flow's definitions and rules in the core's order (spec section 4), lowers its
// conditions in place and refuses a flow that breaks a rule: every edge of a refused flow is disabled and
// FieldError names the first problem. A flow with no definitions is left exactly as it was.
func applyDefinitions(graph *Graph, meta map[string]string) {
	defines := false
	for key := range meta {
		if strings.HasPrefix(key, fieldPrefix) {
			defines = true
		}
	}
	if !defines {
		return
	}
	problems, rules, definitions := coreAnalysis(*graph, meta)
	if len(problems) == 0 {
		graph.Fields = definitions
		routed := map[string]bool{}
		for _, rule := range rules {
			for _, atom := range coreAtoms(rule.decoded, nil) {
				if _, defined := definitions[atom.field]; defined {
					routed[atom.field] = true
				}
			}
		}
		graph.Routed = make([]string, 0, len(routed))
		for name := range routed {
			graph.Routed = append(graph.Routed, name)
		}
		sort.Strings(graph.Routed)
		for _, name := range graph.NodeOrder {
			node, ok := graph.Nodes[name]
			if !ok {
				continue
			}
			for index, edge := range node.Edges {
				lowered, found := lowerConditionChecked(edge.Condition, definitions)
				if found != nil {
					// outside the core's syntax: a sign outside parentheses, a literal between two scales
					found.Text = fmt.Sprintf("%s: %q: %s", name, edge.Condition, found.Text)
					problems = append(problems, *found)
				}
				node.Edges[index].Condition = lowered
			}
			graph.Nodes[name] = node
		}
	}
	if len(problems) == 0 {
		return
	}
	first := problems[0]
	message := "the flow breaks its field definitions: "
	texts := make([]string, len(problems))
	for index, found := range problems {
		texts[index] = found.Text
	}
	if first.Cause == "policy:definition" {
		message = first.Text
	} else {
		message += strings.Join(texts, "; ")
	}
	code, _ := CoreCauseCode(first.Cause)
	graph.FieldError = &FieldDefinitionError{Message: message, Cause: first.Cause, Field: first.Field, Reason: first.Reason, Code: code, Problems: problems}
	graph.Refused = message
	graph.Fields, graph.Routed = map[string]FieldDefinition{}, nil
	for name, node := range graph.Nodes {
		for index := range node.Edges {
			node.Edges[index].Condition = "never"
		}
		graph.Nodes[name] = node
	}
}
