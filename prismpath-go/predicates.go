package prismpath

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode"
)

// TokenType represents predicate AST token types.
type TokenType int

const (
	tokNum TokenType = iota
	tokStr
	tokName
	tokOp
	tokLParen
	tokRParen
	tokLBracket
	tokRBracket
	tokComma
)

type token struct {
	kind TokenType
	val  interface{}
	str  string
}

const maxPredicateDepth = 50 // the same bound the Python kernel enforces

// exprNode is one node of a predicate expression tree. It is deliberately spelled
// apart from Node, which in this package is a node of the flow graph.
type exprNode interface {
	eval(ctx map[string]interface{}, depth int) (interface{}, error)
}

type constNode struct{ val interface{} }

func (expr *constNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > maxPredicateDepth {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	return expr.val, nil
}

type varNode struct{ name string }

func (expr *varNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > maxPredicateDepth {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	if value, ok := ctx[expr.name]; ok {
		return value, nil
	}
	return nil, nil
}

type notNode struct{ child exprNode }

func (expr *notNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > maxPredicateDepth {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	value, err := expr.child.eval(ctx, depth+1)
	if err != nil {
		return nil, err
	}
	return !pyTruthy(value), nil
}

type binOpNode struct {
	op    string
	left  exprNode
	right exprNode
}

func (expr *binOpNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > maxPredicateDepth {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	switch expr.op {
	case "and":
		lVal, err := expr.left.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		if !pyTruthy(lVal) {
			rVal, err := expr.right.eval(ctx, depth+1)
			if err != nil {
				return nil, err
			}
			_ = rVal
			return false, nil
		}
		rVal, err := expr.right.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		return pyTruthy(rVal), nil

	case "or":
		lVal, err := expr.left.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		if pyTruthy(lVal) {
			rVal, err := expr.right.eval(ctx, depth+1)
			if err != nil {
				return nil, err
			}
			_ = rVal
			return true, nil
		}
		rVal, err := expr.right.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		return pyTruthy(rVal), nil
	}

	lVal, err := expr.left.eval(ctx, depth+1)
	if err != nil {
		return nil, err
	}
	rVal, err := expr.right.eval(ctx, depth+1)
	if err != nil {
		return nil, err
	}

	switch expr.op {
	case "==":
		return pyEq(lVal, rVal), nil
	case "!=":
		return !pyEq(lVal, rVal), nil
	case "<":
		res, ok := pyOrder(lVal, rVal)
		return ok && res < 0, nil
	case "<=":
		res, ok := pyOrder(lVal, rVal)
		return ok && res <= 0, nil
	case ">":
		res, ok := pyOrder(lVal, rVal)
		return ok && res > 0, nil
	case ">=":
		res, ok := pyOrder(lVal, rVal)
		return ok && res >= 0, nil
	case "in":
		res, _ := pyIn(lVal, rVal)
		return res, nil
	case "not in":
		res, _ := pyIn(lVal, rVal)
		return !res, nil
	default:
		return nil, newPredErr("unknown operator %s", expr.op)
	}
}

type chainedCmpNode struct {
	ops   []string
	exprs []exprNode
}

func (expr *chainedCmpNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > maxPredicateDepth {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	if len(expr.exprs) == 0 {
		return true, nil
	}
	left, err := expr.exprs[0].eval(ctx, depth+1)
	if err != nil {
		return nil, err
	}
	for index := 0; index < len(expr.ops); index++ {
		op := expr.ops[index]
		right, err := expr.exprs[index+1].eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		var match bool
		switch op {
		case "==":
			match = pyEq(left, right)
		case "!=":
			match = !pyEq(left, right)
		case "<":
			res, ok := pyOrder(left, right)
			match = ok && res < 0
		case "<=":
			res, ok := pyOrder(left, right)
			match = ok && res <= 0
		case ">":
			res, ok := pyOrder(left, right)
			match = ok && res > 0
		case ">=":
			res, ok := pyOrder(left, right)
			match = ok && res >= 0
		case "in":
			match, _ = pyIn(left, right)
		case "not in":
			res, _ := pyIn(left, right)
			match = !res
		}
		if !match {
			return false, nil
		}
		left = right
	}
	return true, nil
}

type listNode struct{ elems []exprNode }

func (expr *listNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > maxPredicateDepth {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	res := make([]interface{}, len(expr.elems))
	for index, element := range expr.elems {
		value, err := element.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		res[index] = value
	}
	return res, nil
}

type tupleNode struct{ elems []exprNode }

func (expr *tupleNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > maxPredicateDepth {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	res := make([]interface{}, len(expr.elems))
	for index, element := range expr.elems {
		value, err := element.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		res[index] = value
	}
	return res, nil
}

// Python Semantics Implementations

func pyTruthy(value interface{}) bool {
	if value == nil {
		return false
	}
	switch val := value.(type) {
	case bool:
		return val
	case int:
		return val != 0
	case int64:
		return val != 0
	case float64:
		return val != 0
	case string:
		return len(val) > 0
	case []interface{}:
		return len(val) > 0
	case map[string]interface{}:
		return len(val) > 0
	case EllipsisType:
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Array, reflect.Slice, reflect.Map:
		return rv.Len() > 0
	}
	return true
}

func toFloat(value interface{}) (float64, bool) {
	switch val := value.(type) {
	case bool:
		if val {
			return 1.0, true
		}
		return 0.0, true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case float64:
		return val, true
	}
	return 0, false
}

func pyEq(left, right interface{}) bool {
	if left == Ellipsis || right == Ellipsis {
		return false
	}
	if left == nil && right == nil {
		return true
	}
	if left == nil || right == nil {
		return false
	}
	leftFloat, leftOk := toFloat(left)
	rightFloat, rightOk := toFloat(right)
	if leftOk && rightOk {
		return leftFloat == rightFloat
	}
	leftStr, leftIsStr := left.(string)
	rightStr, rightIsStr := right.(string)
	if leftIsStr && rightIsStr {
		return leftStr == rightStr
	}
	leftSlice, leftIsSlice := toSlice(left)
	rightSlice, rightIsSlice := toSlice(right)
	if leftIsSlice && rightIsSlice {
		if len(leftSlice) != len(rightSlice) {
			return false
		}
		for index := range leftSlice {
			if !pyEq(leftSlice[index], rightSlice[index]) {
				return false
			}
		}
		return true
	}
	leftMap, leftIsMap := toMap(left)
	rightMap, rightIsMap := toMap(right)
	if leftIsMap && rightIsMap {
		if len(leftMap) != len(rightMap) {
			return false
		}
		for key, value := range leftMap {
			rightValue, ok := rightMap[key]
			if !ok || !pyEq(value, rightValue) {
				return false
			}
		}
		return true
	}
	return false
}

func toSlice(value interface{}) ([]interface{}, bool) {
	if slice, ok := value.([]interface{}); ok {
		return slice, true
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		res := make([]interface{}, rv.Len())
		for index := 0; index < rv.Len(); index++ {
			res[index] = rv.Index(index).Interface()
		}
		return res, true
	}
	return nil, false
}

func toMap(value interface{}) (map[string]interface{}, bool) {
	if mapping, ok := value.(map[string]interface{}); ok {
		return mapping, true
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Map {
		res := make(map[string]interface{})
		for _, key := range rv.MapKeys() {
			res[fmt.Sprint(key.Interface())] = rv.MapIndex(key).Interface()
		}
		return res, true
	}
	return nil, false
}

func pyOrder(left, right interface{}) (int, bool) {
	leftFloat, leftOk := toFloat(left)
	rightFloat, rightOk := toFloat(right)
	if leftOk && rightOk {
		if math.IsNaN(leftFloat) || math.IsNaN(rightFloat) {
			return 0, false
		}
		if leftFloat < rightFloat {
			return -1, true
		}
		if leftFloat > rightFloat {
			return 1, true
		}
		return 0, true
	}
	leftStr, leftIsStr := left.(string)
	rightStr, rightIsStr := right.(string)
	if leftIsStr && rightIsStr {
		if leftStr < rightStr {
			return -1, true
		}
		if leftStr > rightStr {
			return 1, true
		}
		return 0, true
	}
	leftSlice, leftIsSlice := toSlice(left)
	rightSlice, rightIsSlice := toSlice(right)
	if leftIsSlice && rightIsSlice {
		minLen := len(leftSlice)
		if len(rightSlice) < minLen {
			minLen = len(rightSlice)
		}
		for index := 0; index < minLen; index++ {
			if pyEq(leftSlice[index], rightSlice[index]) {
				continue
			}
			cmp, ok := pyOrder(leftSlice[index], rightSlice[index])
			if !ok {
				return 0, false
			}
			return cmp, true
		}
		if len(leftSlice) < len(rightSlice) {
			return -1, true
		}
		if len(leftSlice) > len(rightSlice) {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func pyIn(left, right interface{}) (bool, bool) {
	if right == nil {
		return false, false
	}
	if rightStr, ok := right.(string); ok {
		if leftStr, ok := left.(string); ok {
			return strings.Contains(rightStr, leftStr), true
		}
		return false, false
	}
	if rightSlice, ok := toSlice(right); ok {
		for _, item := range rightSlice {
			if pyEq(left, item) {
				return true, true
			}
		}
		return false, true
	}
	if rightMap, ok := toMap(right); ok {
		if leftStr, ok := left.(string); ok {
			_, exists := rightMap[leftStr]
			return exists, true
		}
		return false, false
	}
	return false, false
}

// Tokenizer & Parser

func tokenize(src string) ([]token, error) {
	var toks []token
	pos := 0
	srcLen := len(src)
	for pos < srcLen {
		ch := rune(src[pos])
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			pos++
			continue
		}
		if unicode.IsLetter(ch) || ch == '_' {
			if (ch == 'r' || ch == 'R') && pos+1 < srcLen && (src[pos+1] == '\'' || src[pos+1] == '"') {
				quoteByte := src[pos+1]
				scan := pos + 2
				var sb strings.Builder
				for scan < srcLen && src[scan] != quoteByte {
					sb.WriteByte(src[scan])
					scan++
				}
				if scan >= srcLen {
					return nil, newPredErr("unterminated string in predicate")
				}
				toks = append(toks, token{kind: tokStr, val: sb.String(), str: sb.String()})
				pos = scan + 1
				continue
			}
			if (ch == 'b' || ch == 'B') && pos+1 < srcLen && (src[pos+1] == '\'' || src[pos+1] == '"') {
				return nil, newPredErr("bytes literals are not supported in predicates")
			}
			scan := pos + 1
			for scan < srcLen && (unicode.IsLetter(rune(src[scan])) || unicode.IsDigit(rune(src[scan])) || src[scan] == '_') {
				scan++
			}
			name := src[pos:scan]
			if pyKeywords[name] {
				return nil, newPredErr("keyword %s is not permitted in predicates", name)
			}
			toks = append(toks, token{kind: tokName, val: name, str: name})
			pos = scan
			continue
		}
		if unicode.IsDigit(ch) || (ch == '.' && pos+1 < srcLen && unicode.IsDigit(rune(src[pos+1]))) {
			scan := pos
			radix := 10
			if ch == '0' && pos+1 < srcLen && (src[pos+1] == 'x' || src[pos+1] == 'X' || src[pos+1] == 'o' || src[pos+1] == 'O' || src[pos+1] == 'b' || src[pos+1] == 'B') {
				rChar := strings.ToLower(string(src[pos+1]))
				if rChar == "x" {
					radix = 16
				} else if rChar == "o" {
					radix = 8
				} else {
					radix = 2
				}
				scan = pos + 2
				bodyStart := scan
				for scan < srcLen && (unicode.IsDigit(rune(src[scan])) || src[scan] == '_' || (radix == 16 && strings.ContainsRune("abcdefABCDEF", rune(src[scan])))) {
					scan++
				}
				body := strings.ReplaceAll(src[bodyStart:scan], "_", "")
				if body == "" {
					return nil, newPredErr("malformed numeric literal in predicate")
				}
				val, err := strconv.ParseInt(body, radix, 64)
				if err != nil {
					return nil, newPredErr("malformed numeric literal in predicate")
				}
				toks = append(toks, token{kind: tokNum, val: val, str: src[pos:scan]})
				pos = scan
				continue
			}
			hasDot := false
			for scan < srcLen && (unicode.IsDigit(rune(src[scan])) || src[scan] == '_') {
				scan++
			}
			if scan < srcLen && src[scan] == '.' {
				hasDot = true
				scan++
				for scan < srcLen && (unicode.IsDigit(rune(src[scan])) || src[scan] == '_') {
					scan++
				}
			}
			if scan < srcLen && (src[scan] == 'e' || src[scan] == 'E') {
				hasDot = true
				expScan := scan + 1
				if expScan < srcLen && (src[expScan] == '+' || src[expScan] == '-') {
					expScan++
				}
				if expScan < srcLen && unicode.IsDigit(rune(src[expScan])) {
					expScan++
					for expScan < srcLen && (unicode.IsDigit(rune(src[expScan])) || src[expScan] == '_') {
						expScan++
					}
					scan = expScan
				}
			}
			if scan < srcLen && (src[scan] == 'j' || src[scan] == 'J') {
				return nil, newPredErr("complex literals are not supported in predicates")
			}
			numStr := strings.ReplaceAll(src[pos:scan], "_", "")
			if hasDot {
				val, err := strconv.ParseFloat(numStr, 64)
				if err != nil {
					return nil, newPredErr("malformed numeric literal in predicate")
				}
				toks = append(toks, token{kind: tokNum, val: val, str: numStr})
			} else {
				val, err := strconv.ParseInt(numStr, 10, 64)
				if err != nil {
					return nil, newPredErr("malformed numeric literal in predicate")
				}
				toks = append(toks, token{kind: tokNum, val: val, str: numStr})
			}
			pos = scan
			continue
		}
		if ch == '\'' || ch == '"' {
			quote := ch
			scan := pos + 1
			var sb strings.Builder
			for scan < srcLen && rune(src[scan]) != quote {
				if src[scan] == '\\' && scan+1 < srcLen {
					scan++
					esc := src[scan]
					switch esc {
					case 'n':
						sb.WriteByte('\n')
					case 't':
						sb.WriteByte('\t')
					case 'r':
						sb.WriteByte('\r')
					case '0':
						sb.WriteByte(0)
					case 'a':
						sb.WriteByte('\a')
					case 'b':
						sb.WriteByte('\b')
					case 'f':
						sb.WriteByte('\f')
					case 'v':
						sb.WriteByte('\v')
					case '\\':
						sb.WriteByte('\\')
					case '\'':
						sb.WriteByte('\'')
					case '"':
						sb.WriteByte('"')
					case 'x':
						if scan+2 < srcLen {
							hexVal, err := strconv.ParseInt(src[scan+1:scan+3], 16, 32)
							if err == nil {
								sb.WriteByte(byte(hexVal))
								scan += 2
							} else {
								sb.WriteString("\\x")
							}
						} else {
							sb.WriteString("\\x")
						}
					case 'u':
						if scan+4 < srcLen {
							hexVal, err := strconv.ParseInt(src[scan+1:scan+5], 16, 32)
							if err == nil {
								sb.WriteRune(rune(hexVal))
								scan += 4
							} else {
								sb.WriteString("\\u")
							}
						} else {
							sb.WriteString("\\u")
						}
					default:
						sb.WriteByte('\\')
						sb.WriteByte(esc)
					}
				} else {
					sb.WriteByte(src[scan])
				}
				scan++
			}
			if scan >= srcLen {
				return nil, newPredErr("unterminated string in predicate")
			}
			toks = append(toks, token{kind: tokStr, val: sb.String(), str: sb.String()})
			pos = scan + 1
			continue
		}

		if strings.HasPrefix(src[pos:], "==") || strings.HasPrefix(src[pos:], "!=") || strings.HasPrefix(src[pos:], "<=") || strings.HasPrefix(src[pos:], ">=") {
			toks = append(toks, token{kind: tokOp, val: src[pos : pos+2], str: src[pos : pos+2]})
			pos += 2
			continue
		}
		if ch == '<' || ch == '>' {
			toks = append(toks, token{kind: tokOp, val: string(ch), str: string(ch)})
			pos++
			continue
		}
		if ch == '(' {
			toks = append(toks, token{kind: tokLParen, str: "("})
			pos++
			continue
		}
		if ch == ')' {
			toks = append(toks, token{kind: tokRParen, str: ")"})
			pos++
			continue
		}
		if ch == '[' {
			toks = append(toks, token{kind: tokLBracket, str: "["})
			pos++
			continue
		}
		if ch == ']' {
			toks = append(toks, token{kind: tokRBracket, str: "]"})
			pos++
			continue
		}
		if ch == ',' {
			toks = append(toks, token{kind: tokComma, str: ","})
			pos++
			continue
		}
		if ch == '-' || ch == '+' {
			// Fold a unary sign onto a base-10 INTEGER literal, mirroring
			// predicates.fold_unary_signs (SPEC §4.3) and the JS/Rust twins: the sign must be
			// in operand position (start of the predicate, or right after an operator, '(',
			// '[', ',', or an operator-keyword) and directly precede an integer. A sign on a
			// float, a field, or in a binary-arithmetic position is left as unrecognized
			// syntax -> PredicateError, exactly as before — so -0.0, x - 1, and -y stay out.
			unary := len(toks) == 0
			if !unary {
				prev := toks[len(toks)-1]
				switch prev.kind {
				case tokOp, tokLParen, tokLBracket, tokComma:
					unary = true
				case tokName:
					switch prev.str {
					case "and", "or", "not", "in":
						unary = true
					}
				}
			}
			if unary && pos+1 < srcLen && unicode.IsDigit(rune(src[pos+1])) {
				scan := pos + 1
				for scan < srcLen && (unicode.IsDigit(rune(src[scan])) || src[scan] == '_') {
					scan++
				}
				// A trailing '.', exponent, complex suffix, or identifier char means it is not
				// a plain base-10 integer (float / 0x.. / 1j) — leave the sign to be rejected.
				foldable := true
				if scan < srcLen {
					nextChar := rune(src[scan])
					if nextChar == '.' || nextChar == 'e' || nextChar == 'E' || nextChar == 'j' || nextChar == 'J' || unicode.IsLetter(nextChar) || nextChar == '_' {
						foldable = false
					}
				}
				if foldable {
					body := strings.ReplaceAll(src[pos+1:scan], "_", "")
					if val, err := strconv.ParseInt(body, 10, 64); err == nil {
						if ch == '-' {
							val = -val
						}
						toks = append(toks, token{kind: tokNum, val: val, str: src[pos:scan]})
						pos = scan
						continue
					}
				}
			}
			return nil, newPredErr("unrecognized syntax in predicate: %s", string(ch))
		}
		if strings.HasPrefix(src[pos:], "...") {
			toks = append(toks, token{kind: tokName, val: "...", str: "..."})
			pos += 3
			continue
		}
		return nil, newPredErr("unrecognized syntax in predicate: %s", string(ch))
	}
	return toks, nil
}

// Parser

type parser struct {
	toks []token
	pos  int
}

func (parseState *parser) peek() *token {
	if parseState.pos < len(parseState.toks) {
		return &parseState.toks[parseState.pos]
	}
	return nil
}

func (parseState *parser) next() *token {
	tok := parseState.peek()
	if tok != nil {
		parseState.pos++
	}
	return tok
}

func (parseState *parser) parseExpr() (exprNode, error) {
	expr, err := parseState.parseOr()
	if err != nil {
		return nil, err
	}
	// Top-level comma is a Python tuple: `when done, verified` is (done, verified),
	// non-empty and therefore ALWAYS truthy (a real trap, but parity first).
	if tok := parseState.peek(); tok != nil && tok.kind == tokComma {
		elems := []exprNode{expr}
		for parseState.peek() != nil && parseState.peek().kind == tokComma {
			parseState.next() // consume comma
			if parseState.peek() == nil {
				break // trailing comma, e.g. `x,`
			}
			element, err := parseState.parseOr()
			if err != nil {
				return nil, err
			}
			elems = append(elems, element)
		}
		expr = &tupleNode{elems: elems}
	}
	if parseState.pos < len(parseState.toks) {
		return nil, newPredErr("unexpected token in predicate")
	}
	return expr, nil
}

func (parseState *parser) parseOr() (exprNode, error) {
	left, err := parseState.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		tok := parseState.peek()
		if tok != nil && tok.kind == tokName && tok.val == "or" {
			parseState.next()
			right, err := parseState.parseAnd()
			if err != nil {
				return nil, err
			}
			left = &binOpNode{op: "or", left: left, right: right}
		} else {
			break
		}
	}
	return left, nil
}

func (parseState *parser) parseAnd() (exprNode, error) {
	left, err := parseState.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		tok := parseState.peek()
		if tok != nil && tok.kind == tokName && tok.val == "and" {
			parseState.next()
			right, err := parseState.parseNot()
			if err != nil {
				return nil, err
			}
			left = &binOpNode{op: "and", left: left, right: right}
		} else {
			break
		}
	}
	return left, nil
}

func (parseState *parser) parseNot() (exprNode, error) {
	tok := parseState.peek()
	if tok != nil && tok.kind == tokName && tok.val == "not" {
		parseState.next()
		child, err := parseState.parseNot()
		if err != nil {
			return nil, err
		}
		return &notNode{child: child}, nil
	}
	return parseState.parseCmp()
}

func (parseState *parser) parseCmp() (exprNode, error) {
	left, err := parseState.parsePrimary()
	if err != nil {
		return nil, err
	}

	var ops []string
	exprs := []exprNode{left}

	for {
		tok := parseState.peek()
		if tok == nil {
			break
		}
		opStr := ""
		if tok.kind == tokOp {
			opStr = fmt.Sprint(tok.val)
			parseState.next()
		} else if tok.kind == tokName && tok.val == "in" {
			opStr = "in"
			parseState.next()
		} else if tok.kind == tokName && tok.val == "not" {
			parseState.next()
			nextTok := parseState.peek()
			if nextTok != nil && nextTok.kind == tokName && nextTok.val == "in" {
				parseState.next()
				opStr = "not in"
			} else {
				return nil, newPredErr("expected 'in' after 'not'")
			}
		} else {
			break
		}

		right, err := parseState.parsePrimary()
		if err != nil {
			return nil, err
		}
		ops = append(ops, opStr)
		exprs = append(exprs, right)
	}

	if len(ops) == 0 {
		return left, nil
	}
	if len(ops) == 1 {
		return &binOpNode{op: ops[0], left: exprs[0], right: exprs[1]}, nil
	}
	return &chainedCmpNode{ops: ops, exprs: exprs}, nil
}

func (parseState *parser) parsePrimary() (exprNode, error) {
	tok := parseState.next()
	if tok == nil {
		return nil, newPredErr("unexpected end of predicate")
	}

	switch tok.kind {
	case tokNum, tokStr:
		return &constNode{val: tok.val}, nil
	case tokName:
		name := fmt.Sprint(tok.val)
		if name == "True" {
			return &constNode{val: true}, nil
		}
		if name == "False" {
			return &constNode{val: false}, nil
		}
		if name == "None" {
			return &constNode{val: nil}, nil
		}
		if name == "..." {
			return &constNode{val: Ellipsis}, nil
		}
		return &varNode{name: name}, nil
	case tokLBracket:
		var elems []exprNode
		if parseState.peek() != nil && parseState.peek().kind != tokRBracket {
			for {
				element, err := parseState.parseOr()
				if err != nil {
					return nil, err
				}
				elems = append(elems, element)
				if parseState.peek() != nil && parseState.peek().kind == tokComma {
					parseState.next()
					if parseState.peek() != nil && parseState.peek().kind == tokRBracket {
						break
					}
				} else {
					break
				}
			}
		}
		if parseState.next() == nil || parseState.peek() == nil && parseState.toks[parseState.pos-1].kind != tokRBracket {
			// consume RBracket
		}
		return &listNode{elems: elems}, nil
	case tokLParen:
		if parseState.peek() != nil && parseState.peek().kind == tokRParen {
			parseState.next()
			return &tupleNode{elems: nil}, nil
		}
		element, err := parseState.parseOr()
		if err != nil {
			return nil, err
		}
		if parseState.peek() != nil && parseState.peek().kind == tokComma {
			parseState.next()
			elems := []exprNode{element}
			for parseState.peek() != nil && parseState.peek().kind != tokRParen {
				nextElement, err := parseState.parseOr()
				if err != nil {
					return nil, err
				}
				elems = append(elems, nextElement)
				if parseState.peek() != nil && parseState.peek().kind == tokComma {
					parseState.next()
				} else {
					break
				}
			}
			if parseState.peek() != nil && parseState.peek().kind == tokRParen {
				parseState.next()
			}
			return &tupleNode{elems: elems}, nil
		}
		if parseState.peek() != nil && parseState.peek().kind == tokRParen {
			parseState.next()
		}
		return element, nil
	}

	return nil, newPredErr("unexpected syntax at token %s", tok.str)
}

// EvalCondition evaluates condition string against context map.
func EvalCondition(condition string, ctx map[string]interface{}) (bool, error) {
	expr := exprOf(condition)
	if alwaysSet[strings.ToLower(expr)] {
		return true, nil
	}
	if neverSet[strings.ToLower(expr)] {
		return false, nil
	}

	toks, err := tokenize(expr)
	if err != nil {
		return false, err
	}
	parseState := &parser{toks: toks}
	ast, err := parseState.parseExpr()
	if err != nil {
		return false, err
	}

	res, err := ast.eval(ctx, 0)
	if err != nil {
		return false, err
	}
	return pyTruthy(res), nil
}
