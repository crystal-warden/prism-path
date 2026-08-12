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

// AST Node interface
type node interface {
	eval(ctx map[string]interface{}, depth int) (interface{}, error)
}

type constNode struct{ val interface{} }

func (n *constNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > 50 {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	return n.val, nil
}

type varNode struct{ name string }

func (n *varNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > 50 {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	if v, ok := ctx[n.name]; ok {
		return v, nil
	}
	return nil, nil
}

type notNode struct{ child node }

func (n *notNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > 50 {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	v, err := n.child.eval(ctx, depth+1)
	if err != nil {
		return nil, err
	}
	return !pyTruthy(v), nil
}

type binOpNode struct {
	op    string
	left  node
	right node
}

func (n *binOpNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > 50 {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	switch n.op {
	case "and":
		lVal, err := n.left.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		if !pyTruthy(lVal) {
			rVal, err := n.right.eval(ctx, depth+1)
			if err != nil {
				return nil, err
			}
			_ = rVal
			return false, nil
		}
		rVal, err := n.right.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		return pyTruthy(rVal), nil

	case "or":
		lVal, err := n.left.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		if pyTruthy(lVal) {
			rVal, err := n.right.eval(ctx, depth+1)
			if err != nil {
				return nil, err
			}
			_ = rVal
			return true, nil
		}
		rVal, err := n.right.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		return pyTruthy(rVal), nil
	}

	lVal, err := n.left.eval(ctx, depth+1)
	if err != nil {
		return nil, err
	}
	rVal, err := n.right.eval(ctx, depth+1)
	if err != nil {
		return nil, err
	}

	switch n.op {
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
		return nil, newPredErr("unknown operator %s", n.op)
	}
}

type chainedCmpNode struct {
	ops   []string
	exprs []node
}

func (n *chainedCmpNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > 50 {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	vals := make([]interface{}, len(n.exprs))
	for i, e := range n.exprs {
		v, err := e.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		vals[i] = v
	}
	for i := 0; i < len(n.ops); i++ {
		op := n.ops[i]
		left := vals[i]
		right := vals[i+1]
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
	}
	return true, nil
}

type listNode struct{ elems []node }

func (n *listNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > 50 {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	res := make([]interface{}, len(n.elems))
	for i, e := range n.elems {
		v, err := e.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		res[i] = v
	}
	return res, nil
}

type tupleNode struct{ elems []node }

func (n *tupleNode) eval(ctx map[string]interface{}, depth int) (interface{}, error) {
	if depth > 50 {
		return nil, newPredErr("expression nested too deeply (depth > 50)")
	}
	res := make([]interface{}, len(n.elems))
	for i, e := range n.elems {
		v, err := e.eval(ctx, depth+1)
		if err != nil {
			return nil, err
		}
		res[i] = v
	}
	return res, nil
}

// Python Semantics Implementations

func pyTruthy(v interface{}) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case int:
		return val != 0
	case int64:
		return val != 0
	case float64:
		return val != 0 && !math.IsNaN(val)
	case string:
		return len(val) > 0
	case []interface{}:
		return len(val) > 0
	case map[string]interface{}:
		return len(val) > 0
	case EllipsisType:
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Array, reflect.Slice, reflect.Map:
		return rv.Len() > 0
	}
	return true
}

func toFloat(v interface{}) (float64, bool) {
	switch val := v.(type) {
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

func pyEq(a, b interface{}) bool {
	if a == Ellipsis || b == Ellipsis {
		return false
	}
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	af, aOk := toFloat(a)
	bf, bOk := toFloat(b)
	if aOk && bOk {
		return af == bf
	}
	as, aIsStr := a.(string)
	bs, bIsStr := b.(string)
	if aIsStr && bIsStr {
		return as == bs
	}
	aSlice, aIsSlice := toSlice(a)
	bSlice, bIsSlice := toSlice(b)
	if aIsSlice && bIsSlice {
		if len(aSlice) != len(bSlice) {
			return false
		}
		for i := range aSlice {
			if !pyEq(aSlice[i], bSlice[i]) {
				return false
			}
		}
		return true
	}
	aMap, aIsMap := toMap(a)
	bMap, bIsMap := toMap(b)
	if aIsMap && bIsMap {
		if len(aMap) != len(bMap) {
			return false
		}
		for k, v := range aMap {
			bv, ok := bMap[k]
			if !ok || !pyEq(v, bv) {
				return false
			}
		}
		return true
	}
	return false
}

func toSlice(v interface{}) ([]interface{}, bool) {
	if s, ok := v.([]interface{}); ok {
		return s, true
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
		res := make([]interface{}, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			res[i] = rv.Index(i).Interface()
		}
		return res, true
	}
	return nil, false
}

func toMap(v interface{}) (map[string]interface{}, bool) {
	if m, ok := v.(map[string]interface{}); ok {
		return m, true
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Map {
		res := make(map[string]interface{})
		for _, k := range rv.MapKeys() {
			res[fmt.Sprint(k.Interface())] = rv.MapIndex(k).Interface()
		}
		return res, true
	}
	return nil, false
}

func pyOrder(a, b interface{}) (int, bool) {
	af, aOk := toFloat(a)
	bf, bOk := toFloat(b)
	if aOk && bOk {
		if math.IsNaN(af) || math.IsNaN(bf) {
			return 0, false
		}
		if af < bf {
			return -1, true
		}
		if af > bf {
			return 1, true
		}
		return 0, true
	}
	as, aIsStr := a.(string)
	bs, bIsStr := b.(string)
	if aIsStr && bIsStr {
		if as < bs {
			return -1, true
		}
		if as > bs {
			return 1, true
		}
		return 0, true
	}
	aSlice, aIsSlice := toSlice(a)
	bSlice, bIsSlice := toSlice(b)
	if aIsSlice && bIsSlice {
		minLen := len(aSlice)
		if len(bSlice) < minLen {
			minLen = len(bSlice)
		}
		for i := 0; i < minLen; i++ {
			if pyEq(aSlice[i], bSlice[i]) {
				continue
			}
			cmp, ok := pyOrder(aSlice[i], bSlice[i])
			if !ok {
				return 0, false
			}
			return cmp, true
		}
		if len(aSlice) < len(bSlice) {
			return -1, true
		}
		if len(aSlice) > len(bSlice) {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func pyIn(a, b interface{}) (bool, bool) {
	if b == nil {
		return false, false
	}
	if bStr, ok := b.(string); ok {
		if aStr, ok := a.(string); ok {
			return strings.Contains(bStr, aStr), true
		}
		return false, false
	}
	if bSlice, ok := toSlice(b); ok {
		for _, item := range bSlice {
			if pyEq(a, item) {
				return true, true
			}
		}
		return false, true
	}
	if bMap, ok := toMap(b); ok {
		if aStr, ok := a.(string); ok {
			_, exists := bMap[aStr]
			return exists, true
		}
		return false, false
	}
	return false, false
}

// Tokenizer & Parser

func tokenize(src string) ([]token, error) {
	var toks []token
	i := 0
	n := len(src)
	for i < n {
		ch := rune(src[i])
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			i++
			continue
		}
		if unicode.IsLetter(ch) || ch == '_' {
			if (ch == 'r' || ch == 'R') && i+1 < n && (src[i+1] == '\'' || src[i+1] == '"') {
				q := src[i+1]
				j := i + 2
				var sb strings.Builder
				for j < n && src[j] != q {
					sb.WriteByte(src[j])
					j++
				}
				if j >= n {
					return nil, newPredErr("unterminated string in predicate")
				}
				toks = append(toks, token{kind: tokStr, val: sb.String(), str: sb.String()})
				i = j + 1
				continue
			}
			if (ch == 'b' || ch == 'B') && i+1 < n && (src[i+1] == '\'' || src[i+1] == '"') {
				return nil, newPredErr("bytes literals are not supported in predicates")
			}
			j := i + 1
			for j < n && (unicode.IsLetter(rune(src[j])) || unicode.IsDigit(rune(src[j])) || src[j] == '_') {
				j++
			}
			name := src[i:j]
			if pyKeywords[name] {
				return nil, newPredErr("keyword %s is not permitted in predicates", name)
			}
			toks = append(toks, token{kind: tokName, val: name, str: name})
			i = j
			continue
		}
		if unicode.IsDigit(ch) || (ch == '.' && i+1 < n && unicode.IsDigit(rune(src[i+1]))) {
			j := i
			radix := 10
			if ch == '0' && i+1 < n && (src[i+1] == 'x' || src[i+1] == 'X' || src[i+1] == 'o' || src[i+1] == 'O' || src[i+1] == 'b' || src[i+1] == 'B') {
				rChar := strings.ToLower(string(src[i+1]))
				if rChar == "x" {
					radix = 16
				} else if rChar == "o" {
					radix = 8
				} else {
					radix = 2
				}
				j = i + 2
				bodyStart := j
				for j < n && (unicode.IsDigit(rune(src[j])) || src[j] == '_' || (radix == 16 && strings.ContainsRune("abcdefABCDEF", rune(src[j])))) {
					j++
				}
				body := strings.ReplaceAll(src[bodyStart:j], "_", "")
				if body == "" {
					return nil, newPredErr("malformed numeric literal in predicate")
				}
				val, err := strconv.ParseInt(body, radix, 64)
				if err != nil {
					return nil, newPredErr("malformed numeric literal in predicate")
				}
				toks = append(toks, token{kind: tokNum, val: val, str: src[i:j]})
				i = j
				continue
			}
			hasDot := false
			for j < n && (unicode.IsDigit(rune(src[j])) || src[j] == '_') {
				j++
			}
			if j < n && src[j] == '.' {
				hasDot = true
				j++
				for j < n && (unicode.IsDigit(rune(src[j])) || src[j] == '_') {
					j++
				}
			}
			if j < n && (src[j] == 'e' || src[j] == 'E') {
				hasDot = true
				k := j + 1
				if k < n && (src[k] == '+' || src[k] == '-') {
					k++
				}
				if k < n && unicode.IsDigit(rune(src[k])) {
					k++
					for k < n && (unicode.IsDigit(rune(src[k])) || src[k] == '_') {
						k++
					}
					j = k
				}
			}
			if j < n && (src[j] == 'j' || src[j] == 'J') {
				return nil, newPredErr("complex literals are not supported in predicates")
			}
			numStr := strings.ReplaceAll(src[i:j], "_", "")
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
			i = j
			continue
		}
		if ch == '\'' || ch == '"' {
			quote := ch
			j := i + 1
			var sb strings.Builder
			for j < n && rune(src[j]) != quote {
				if src[j] == '\\' && j+1 < n {
					j++
					esc := src[j]
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
						if j+2 < n {
							hexVal, err := strconv.ParseInt(src[j+1:j+3], 16, 32)
							if err == nil {
								sb.WriteByte(byte(hexVal))
								j += 2
							} else {
								sb.WriteString("\\x")
							}
						} else {
							sb.WriteString("\\x")
						}
					case 'u':
						if j+4 < n {
							hexVal, err := strconv.ParseInt(src[j+1:j+5], 16, 32)
							if err == nil {
								sb.WriteRune(rune(hexVal))
								j += 4
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
					sb.WriteByte(src[j])
				}
				j++
			}
			if j >= n {
				return nil, newPredErr("unterminated string in predicate")
			}
			toks = append(toks, token{kind: tokStr, val: sb.String(), str: sb.String()})
			i = j + 1
			continue
		}

		if strings.HasPrefix(src[i:], "==") || strings.HasPrefix(src[i:], "!=") || strings.HasPrefix(src[i:], "<=") || strings.HasPrefix(src[i:], ">=") {
			toks = append(toks, token{kind: tokOp, val: src[i : i+2], str: src[i : i+2]})
			i += 2
			continue
		}
		if ch == '<' || ch == '>' {
			toks = append(toks, token{kind: tokOp, val: string(ch), str: string(ch)})
			i++
			continue
		}
		if ch == '(' {
			toks = append(toks, token{kind: tokLParen, str: "("})
			i++
			continue
		}
		if ch == ')' {
			toks = append(toks, token{kind: tokRParen, str: ")"})
			i++
			continue
		}
		if ch == '[' {
			toks = append(toks, token{kind: tokLBracket, str: "["})
			i++
			continue
		}
		if ch == ']' {
			toks = append(toks, token{kind: tokRBracket, str: "]"})
			i++
			continue
		}
		if ch == ',' {
			toks = append(toks, token{kind: tokComma, str: ","})
			i++
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
			if unary && i+1 < n && unicode.IsDigit(rune(src[i+1])) {
				j := i + 1
				for j < n && (unicode.IsDigit(rune(src[j])) || src[j] == '_') {
					j++
				}
				// A trailing '.', exponent, complex suffix, or identifier char means it is not
				// a plain base-10 integer (float / 0x.. / 1j) — leave the sign to be rejected.
				foldable := true
				if j < n {
					c := rune(src[j])
					if c == '.' || c == 'e' || c == 'E' || c == 'j' || c == 'J' || unicode.IsLetter(c) || c == '_' {
						foldable = false
					}
				}
				if foldable {
					body := strings.ReplaceAll(src[i+1:j], "_", "")
					if val, err := strconv.ParseInt(body, 10, 64); err == nil {
						if ch == '-' {
							val = -val
						}
						toks = append(toks, token{kind: tokNum, val: val, str: src[i:j]})
						i = j
						continue
					}
				}
			}
			return nil, newPredErr("unrecognized syntax in predicate: %s", string(ch))
		}
		if strings.HasPrefix(src[i:], "...") {
			toks = append(toks, token{kind: tokName, val: "...", str: "..."})
			i += 3
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

func (p *parser) peek() *token {
	if p.pos < len(p.toks) {
		return &p.toks[p.pos]
	}
	return nil
}

func (p *parser) next() *token {
	t := p.peek()
	if t != nil {
		p.pos++
	}
	return t
}

func (p *parser) parseExpr() (node, error) {
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	// Top-level comma is a Python tuple: `when done, verified` is (done, verified),
	// non-empty and therefore ALWAYS truthy (a real trap, but parity first).
	if t := p.peek(); t != nil && t.kind == tokComma {
		elems := []node{n}
		for p.peek() != nil && p.peek().kind == tokComma {
			p.next() // consume comma
			if p.peek() == nil {
				break // trailing comma, e.g. `x,`
			}
			e, err := p.parseOr()
			if err != nil {
				return nil, err
			}
			elems = append(elems, e)
		}
		n = &tupleNode{elems: elems}
	}
	if p.pos < len(p.toks) {
		return nil, newPredErr("unexpected token in predicate")
	}
	return n, nil
}

func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t != nil && t.kind == tokName && t.val == "or" {
			p.next()
			right, err := p.parseAnd()
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

func (p *parser) parseAnd() (node, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t != nil && t.kind == tokName && t.val == "and" {
			p.next()
			right, err := p.parseNot()
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

func (p *parser) parseNot() (node, error) {
	t := p.peek()
	if t != nil && t.kind == tokName && t.val == "not" {
		p.next()
		child, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &notNode{child: child}, nil
	}
	return p.parseCmp()
}

func (p *parser) parseCmp() (node, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	var ops []string
	exprs := []node{left}

	for {
		t := p.peek()
		if t == nil {
			break
		}
		opStr := ""
		if t.kind == tokOp {
			opStr = fmt.Sprint(t.val)
			p.next()
		} else if t.kind == tokName && t.val == "in" {
			opStr = "in"
			p.next()
		} else if t.kind == tokName && t.val == "not" {
			p.next()
			t2 := p.peek()
			if t2 != nil && t2.kind == tokName && t2.val == "in" {
				p.next()
				opStr = "not in"
			} else {
				return nil, newPredErr("expected 'in' after 'not'")
			}
		} else {
			break
		}

		right, err := p.parsePrimary()
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

func (p *parser) parsePrimary() (node, error) {
	t := p.next()
	if t == nil {
		return nil, newPredErr("unexpected end of predicate")
	}

	switch t.kind {
	case tokNum, tokStr:
		return &constNode{val: t.val}, nil
	case tokName:
		name := fmt.Sprint(t.val)
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
		var elems []node
		if p.peek() != nil && p.peek().kind != tokRBracket {
			for {
				e, err := p.parseOr()
				if err != nil {
					return nil, err
				}
				elems = append(elems, e)
				if p.peek() != nil && p.peek().kind == tokComma {
					p.next()
					if p.peek() != nil && p.peek().kind == tokRBracket {
						break
					}
				} else {
					break
				}
			}
		}
		if p.next() == nil || p.peek() == nil && p.toks[p.pos-1].kind != tokRBracket {
			// consume RBracket
		}
		return &listNode{elems: elems}, nil
	case tokLParen:
		if p.peek() != nil && p.peek().kind == tokRParen {
			p.next()
			return &tupleNode{elems: nil}, nil
		}
		e, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != nil && p.peek().kind == tokComma {
			p.next()
			elems := []node{e}
			for p.peek() != nil && p.peek().kind != tokRParen {
				elem, err := p.parseOr()
				if err != nil {
					return nil, err
				}
				elems = append(elems, elem)
				if p.peek() != nil && p.peek().kind == tokComma {
					p.next()
				} else {
					break
				}
			}
			if p.peek() != nil && p.peek().kind == tokRParen {
				p.next()
			}
			return &tupleNode{elems: elems}, nil
		}
		if p.peek() != nil && p.peek().kind == tokRParen {
			p.next()
		}
		return e, nil
	}

	return nil, newPredErr("unexpected syntax at token %s", t.str)
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
	p := &parser{toks: toks}
	ast, err := p.parseExpr()
	if err != nil {
		return false, err
	}

	res, err := ast.eval(ctx, 0)
	if err != nil {
		return false, err
	}
	return pyTruthy(res), nil
}
