package prismpath

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// canon/2 is the integer only profile of RFC 8785 that docs/design/spec-verified-core.md section 3
// specifies and the Lean reader `Core.readBytes` defines: the documents of the verified core, a policy image
// and a reading. This file is the Go reader and writer, a port of prismpath/kernel/canon2.py held to the same
// frozen vectors (prismpath/portable/conformance/canon2.json).
//
// Canon2Read is the strict reader (the Lean `Core.readCanonical`): it accepts exactly the canonical bytes of
// a canon/2 value. A text is first read as canon/2: JSON (RFC 8259) whose numbers are integers within plus or
// minus 2^53 minus 1 written without a fraction, an exponent or a negative zero, whose objects hold no key
// twice, whose strings hold no lone surrogate escape, and whose arrays and objects nest at most 128 deep. Any
// other input is a *Canon2Error whose Rule is the first rule broken reading left to right: utf8, syntax,
// float, integer-range, negative-zero, duplicate-key, lone-surrogate or depth. A text that reads but is not
// the canonical spelling of its value (whitespace, members out of key order, a needless escape) is refused
// with Rule not-canonical. Canon2Canonicalize is the path for text a person wrote: every rule but the
// spelling, then the canonical bytes, which Canon2Read accepts; no reader calls it.

const (
	canon2Limit    = int64(1)<<53 - 1
	canon2MaxDepth = 128
)

// Canon2Error is a text that is not a canon/2 document, or a value that has no canon/2 form.
type Canon2Error struct {
	Rule   string
	Detail string
}

func (canonErr *Canon2Error) Error() string {
	if canonErr.Detail == "" {
		return "canon/2 " + canonErr.Rule
	}
	return "canon/2 " + canonErr.Rule + ": " + canonErr.Detail
}

func canon2Fail(rule string, detail string) {
	panic(&Canon2Error{Rule: rule, Detail: detail})
}

// canon2Reader reads a text held as code points, so positions and windows count code points as the
// reference does.
type canon2Reader struct {
	cps []rune
	pos int
}

func (reader *canon2Reader) skipWs() {
	for reader.pos < len(reader.cps) {
		char := reader.cps[reader.pos]
		if char != ' ' && char != '\t' && char != '\n' && char != '\r' {
			return
		}
		reader.pos++
	}
}

// peek is the code point at the position, or -1 at the end.
func (reader *canon2Reader) peek() rune {
	if reader.pos < len(reader.cps) {
		return reader.cps[reader.pos]
	}
	return -1
}

func (reader *canon2Reader) startsWith(word string) bool {
	for offset, char := range []rune(word) {
		if reader.pos+offset >= len(reader.cps) || reader.cps[reader.pos+offset] != char {
			return false
		}
	}
	return true
}

func isDigitRune(char rune) bool { return char >= '0' && char <= '9' }

func (reader *canon2Reader) value(depth int) interface{} {
	reader.skipWs()
	char := reader.peek()
	switch {
	case reader.startsWith("null"):
		reader.pos += 4
		return nil
	case reader.startsWith("true"):
		reader.pos += 4
		return true
	case reader.startsWith("false"):
		reader.pos += 5
		return false
	case char == '"':
		reader.pos++
		return reader.str()
	case char == '-':
		reader.pos++
		return reader.number(true)
	case char == '[':
		if depth+1 > canon2MaxDepth {
			canon2Fail("depth", "")
		}
		reader.pos++
		reader.skipWs()
		items := []interface{}{}
		if reader.peek() == ']' {
			reader.pos++
			return items
		}
		items = append(items, reader.value(depth+1))
		for {
			reader.skipWs()
			next := reader.peek()
			if next == ']' {
				reader.pos++
				return items
			}
			if next != ',' {
				canon2Fail("syntax", fmt.Sprintf("expected , or ] at %d", reader.pos))
			}
			reader.pos++
			items = append(items, reader.value(depth+1))
		}
	case char == '{':
		if depth+1 > canon2MaxDepth {
			canon2Fail("depth", "")
		}
		reader.pos++
		reader.skipWs()
		members := map[string]interface{}{}
		if reader.peek() == '}' {
			reader.pos++
			return members
		}
		for {
			reader.skipWs()
			if reader.peek() != '"' {
				canon2Fail("syntax", fmt.Sprintf("expected a key at %d", reader.pos))
			}
			reader.pos++
			key := reader.str()
			if _, seen := members[key]; seen {
				canon2Fail("duplicate-key", fmt.Sprintf("%q", key))
			}
			reader.skipWs()
			if reader.peek() != ':' {
				canon2Fail("syntax", fmt.Sprintf("expected : at %d", reader.pos))
			}
			reader.pos++
			members[key] = reader.value(depth + 1)
			reader.skipWs()
			next := reader.peek()
			if next == '}' {
				reader.pos++
				return members
			}
			if next != ',' {
				canon2Fail("syntax", fmt.Sprintf("expected , or } at %d", reader.pos))
			}
			reader.pos++
		}
	case isDigitRune(char):
		return reader.number(false)
	}
	if char < 0 {
		canon2Fail("syntax", "unexpected end")
	}
	canon2Fail("syntax", fmt.Sprintf("unexpected %q at %d", char, reader.pos))
	return nil
}

// hex4 is the value of four code points at `at` as hex, or -1 when they are not hex.
func (reader *canon2Reader) hex4(at int) int {
	if at+4 > len(reader.cps) {
		return -1
	}
	value := 0
	for _, char := range reader.cps[at : at+4] {
		switch {
		case char >= '0' && char <= '9':
			value = value*16 + int(char-'0')
		case char >= 'a' && char <= 'f':
			value = value*16 + int(char-'a') + 10
		case char >= 'A' && char <= 'F':
			value = value*16 + int(char-'A') + 10
		default:
			return -1
		}
	}
	return value
}

func (reader *canon2Reader) str() string {
	out := []rune{}
	for {
		if reader.pos >= len(reader.cps) {
			canon2Fail("syntax", "unterminated string")
		}
		char := reader.cps[reader.pos]
		if char == '"' {
			reader.pos++
			return string(out)
		}
		if char == '\\' && reader.pos+1 < len(reader.cps) {
			escape := reader.cps[reader.pos+1]
			if escape == 'u' && reader.pos+6 <= len(reader.cps) {
				high := reader.hex4(reader.pos + 2)
				if high < 0 {
					canon2Fail("syntax", "bad \\u escape")
				}
				if high >= 0xd800 && high <= 0xdbff {
					after := reader.pos + 6
					if after+1 < len(reader.cps) && reader.cps[after] == '\\' && reader.cps[after+1] == 'u' && after+6 <= len(reader.cps) {
						low := reader.hex4(after + 2)
						if low < 0 {
							canon2Fail("syntax", "bad \\u escape")
						}
						if low >= 0xdc00 && low <= 0xdfff {
							out = append(out, rune(0x10000+(high-0xd800)*0x400+(low-0xdc00)))
							reader.pos = after + 6
							continue
						}
					}
					canon2Fail("lone-surrogate", "")
				}
				if high >= 0xdc00 && high <= 0xdfff {
					canon2Fail("lone-surrogate", "")
				}
				out = append(out, rune(high))
				reader.pos += 6
				continue
			}
			simple := map[rune]rune{'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}
			if mapped, ok := simple[escape]; ok {
				out = append(out, mapped)
				reader.pos += 2
				continue
			}
			canon2Fail("syntax", "bad escape")
		}
		if char < 0x20 {
			canon2Fail("syntax", "control character in a string")
		}
		out = append(out, char)
		reader.pos++
	}
}

func (reader *canon2Reader) digits() string {
	start := reader.pos
	for reader.pos < len(reader.cps) && isDigitRune(reader.cps[reader.pos]) {
		reader.pos++
	}
	return string(reader.cps[start:reader.pos])
}

func (reader *canon2Reader) number(negative bool) interface{} {
	char := reader.peek()
	var digits string
	switch {
	case char == '0':
		reader.pos++
		digits = "0"
	case isDigitRune(char):
		digits = reader.digits()
	default:
		canon2Fail("syntax", "a number needs a digit")
	}
	fraction, exponent := false, false
	if reader.peek() == '.' {
		reader.pos++
		if reader.digits() == "" {
			canon2Fail("syntax", "a fraction needs a digit")
		}
		fraction = true
	}
	if reader.peek() == 'e' || reader.peek() == 'E' {
		reader.pos++
		if reader.peek() == '+' || reader.peek() == '-' {
			reader.pos++
		}
		if reader.digits() == "" {
			canon2Fail("syntax", "an exponent needs a digit")
		}
		exponent = true
	}
	if fraction || exponent {
		canon2Fail("float", "a number with a fraction or an exponent")
	}
	if negative && digits == "0" {
		canon2Fail("negative-zero", "")
	}
	if len(digits) > 16 {
		canon2Fail("integer-range", digits)
	}
	var magnitude int64
	for _, digit := range digits {
		magnitude = magnitude*10 + int64(digit-'0')
	}
	if magnitude > canon2Limit {
		canon2Fail("integer-range", digits)
	}
	if negative {
		return -magnitude
	}
	return magnitude
}

// Canon2Read reads the canon/2 document in data (strict UTF-8) as nil, bool, int64, string, []interface{}
// or map[string]interface{}, when data is exactly the canonical spelling of that value. The error, if any,
// is a *Canon2Error carrying the first rule broken, or not-canonical.
func Canon2Read(data []byte) (interface{}, error) {
	value, err := canon2Parse(data)
	if err != nil {
		return nil, err
	}
	written, err := Canon2Write(value)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(written, data) {
		return nil, &Canon2Error{Rule: "not-canonical", Detail: "the document reads as canon/2 but is not its canonical spelling"}
	}
	return value, nil
}

// Canon2Canonicalize returns the canonical bytes of the canon/2 value a person wrote in data, in any legal
// spelling (whitespace, member order, escapes); every other rule holds as in Canon2Read, and the result is
// what Canon2Read accepts. A writer's step, never a reader's (prismpath/kernel/canon2.py canonicalize).
func Canon2Canonicalize(data []byte) ([]byte, error) {
	value, err := canon2Parse(data)
	if err != nil {
		return nil, err
	}
	return Canon2Write(value)
}

// canon2Parse reads data by every canon/2 rule but the spelling.
func canon2Parse(data []byte) (result interface{}, err error) {
	if !utf8.Valid(data) {
		return nil, &Canon2Error{Rule: "utf8"}
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			canonErr, ok := recovered.(*Canon2Error)
			if !ok {
				panic(recovered)
			}
			result, err = nil, canonErr
		}
	}()
	reader := &canon2Reader{cps: []rune(string(data))}
	value := reader.value(0)
	reader.skipWs()
	if reader.pos != len(reader.cps) {
		canon2Fail("syntax", fmt.Sprintf("trailing text at %d", reader.pos))
	}
	return value, nil
}

func canon2WriteString(text string, out *strings.Builder) {
	out.WriteByte('"')
	for _, char := range text {
		switch {
		case char == '"':
			out.WriteString("\\\"")
		case char == '\\':
			out.WriteString("\\\\")
		case char == '\b':
			out.WriteString("\\b")
		case char == '\t':
			out.WriteString("\\t")
		case char == '\n':
			out.WriteString("\\n")
		case char == '\f':
			out.WriteString("\\f")
		case char == '\r':
			out.WriteString("\\r")
		case char < 0x20:
			fmt.Fprintf(out, "\\u%04x", char)
		default:
			out.WriteRune(char)
		}
	}
	out.WriteByte('"')
}

func canon2WriteValue(value interface{}, depth int, out *strings.Builder) {
	switch typed := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if typed {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case int:
		canon2WriteValue(int64(typed), depth, out)
	case int64:
		if typed > canon2Limit || typed < -canon2Limit {
			canon2Fail("integer-range", "an integer beyond plus or minus 2^53 minus 1; write it as a decimal string")
		}
		fmt.Fprintf(out, "%d", typed)
	case float64:
		if typed != float64(int64(typed)) {
			canon2Fail("float", "canon/2 has no float; write a decimal string or an integer of a stated unit")
		}
		canon2WriteValue(int64(typed), depth, out)
	case string:
		if !utf8.ValidString(typed) {
			canon2Fail("lone-surrogate", "a string holds bytes with no UTF-8 form")
		}
		canon2WriteString(typed, out)
	case []interface{}:
		if depth+1 > canon2MaxDepth {
			canon2Fail("depth", "")
		}
		out.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				out.WriteByte(',')
			}
			canon2WriteValue(item, depth+1, out)
		}
		out.WriteByte(']')
	case map[string]interface{}:
		if depth+1 > canon2MaxDepth {
			canon2Fail("depth", "")
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		// RFC 8785 sorts members by the UTF-16 code units of their keys
		sort.Slice(keys, func(left, right int) bool {
			leftUnits, rightUnits := utf16.Encode([]rune(keys[left])), utf16.Encode([]rune(keys[right]))
			for index := 0; index < len(leftUnits) && index < len(rightUnits); index++ {
				if leftUnits[index] != rightUnits[index] {
					return leftUnits[index] < rightUnits[index]
				}
			}
			return len(leftUnits) < len(rightUnits)
		})
		out.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				out.WriteByte(',')
			}
			canon2WriteString(key, out)
			out.WriteByte(':')
			canon2WriteValue(typed[key], depth+1, out)
		}
		out.WriteByte('}')
	default:
		panic(fmt.Sprintf("%T has no canon/2 form", value))
	}
}

// Canon2Write writes the canonical canon/2 bytes of a value (nil, bool, int, int64, an integral float64,
// string, []interface{} or map[string]interface{}): no whitespace, members in the order of the UTF-16 code
// units of their keys, strings as raw UTF-8 with only the quote, the backslash and the control characters
// escaped, integers in decimal. It refuses every value Canon2Read would refuse.
func Canon2Write(value interface{}) (written []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			canonErr, ok := recovered.(*Canon2Error)
			if !ok {
				panic(recovered)
			}
			written, err = nil, canonErr
		}
	}()
	var out strings.Builder
	canon2WriteValue(value, 0, &out)
	return []byte(out.String()), nil
}
