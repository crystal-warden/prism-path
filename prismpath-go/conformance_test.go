package prismpath

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type predicateCase struct {
	Cond   string                 `json:"cond"`
	Ctx    map[string]interface{} `json:"ctx"`
	Expect interface{}            `json:"expect"`
}

type predicatesCorpus struct {
	Cases []predicateCase `json:"cases"`
}

type flowCase struct {
	Name     string                   `json:"name"`
	Flow     string                   `json:"flow"`
	Script   map[string][]interface{} `json:"script"`
	MaxSteps *int                     `json:"maxSteps"`
	Start    *string                  `json:"start"`
	State    map[string]interface{}   `json:"state"`
	Opts     map[string]interface{}   `json:"opts"`
	Expect   struct {
		Path        []string    `json:"path"`
		Stopped     string      `json:"stopped"`
		PendingNode *string     `json:"pending_node"`
		Spawn       interface{} `json:"spawn"`
	} `json:"expect"`
}

type flowsCorpus struct {
	Cases []flowCase `json:"cases"`
}

func TestPredicatesConformance(test *testing.T) {
	path := filepath.Join("..", "prismpath", "portable", "conformance", "predicates.json")
	data, err := os.ReadFile(path)
	if err != nil {
		test.Fatalf("failed to read predicates.json: %v", err)
	}

	var corpus predicatesCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		test.Fatalf("failed to unmarshal predicates.json: %v", err)
	}

	passed := 0
	for _, predCase := range corpus.Cases {
		got, err := EvalCondition(predCase.Cond, predCase.Ctx)
		var gotResult interface{}
		if err != nil {
			gotResult = "ERROR"
		} else {
			gotResult = got
		}

		if reflect.DeepEqual(gotResult, predCase.Expect) {
			passed++
		} else {
			test.Errorf("PRED MISMATCH cond=%q ctx=%v\n  expect=%v got=%v", predCase.Cond, predCase.Ctx, predCase.Expect, gotResult)
		}
	}

	test.Logf("predicates: %d/%d passed", passed, len(corpus.Cases))
}

func TestFlowsConformance(test *testing.T) {
	path := filepath.Join("..", "prismpath", "portable", "conformance", "flows.json")
	data, err := os.ReadFile(path)
	if err != nil {
		test.Fatalf("failed to read flows.json: %v", err)
	}

	var corpus flowsCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		test.Fatalf("failed to unmarshal flows.json: %v", err)
	}

	passed := 0
	skipped := 0
	for _, fx := range corpus.Cases {
		// A case that carries opts sets an engine option this kernel does not take (the type gate, the
		// transcript bound, a run id); those cases are for the engines that implement the options.
		if fx.Opts != nil {
			skipped++
			continue
		}
		graph := Parse(fx.Flow)
		used := make(map[string]int)

		scriptedWorker := func(node string, inst string, state map[string]interface{}) (interface{}, error) {
			seq, exists := fx.Script[node]
			if !exists || len(seq) == 0 {
				return map[string]interface{}{"text": node}, nil
			}
			idx := used[node]
			used[node] = idx + 1
			if idx >= len(seq) {
				idx = len(seq) - 1
			}
			outcome := seq[idx]

			if outcomeMap, ok := outcome.(map[string]interface{}); ok {
				if rMsg, ok := outcomeMap["__raise__"].(string); ok {
					return nil, errors.New(rMsg)
				}
			}
			return outcome, nil
		}

		opts := RunOptions{
			State: fx.State,
		}
		if fx.MaxSteps != nil {
			opts.MaxSteps = *fx.MaxSteps
		}
		if fx.Start != nil {
			opts.Start = *fx.Start
		}

		res, err := Run(graph, scriptedWorker, opts)
		if err != nil {
			test.Errorf("FLOW ERROR %s: %v", fx.Name, err)
			continue
		}

		expectedPending := fx.Expect.PendingNode
		if expectedPending != nil && *expectedPending == "" {
			expectedPending = nil
		}

		pendingMatch := (res.PendingNode == nil && expectedPending == nil) ||
			(res.PendingNode != nil && expectedPending != nil && *res.PendingNode == *expectedPending)

		pathMatch := reflect.DeepEqual(res.Path, fx.Expect.Path)
		stoppedMatch := res.Stopped == fx.Expect.Stopped
		spawnMatch := reflect.DeepEqual(res.Spawn, fx.Expect.Spawn)

		if pathMatch && stoppedMatch && pendingMatch && spawnMatch {
			passed++
		} else {
			test.Errorf("FLOW MISMATCH %s\n  expect path=%v stopped=%v pending=%v spawn=%v\n  got    path=%v stopped=%v pending=%v spawn=%v",
				fx.Name, fx.Expect.Path, fx.Expect.Stopped, expectedPending, fx.Expect.Spawn,
				res.Path, res.Stopped, res.PendingNode, res.Spawn)
		}
	}

	test.Logf("flows: %d/%d passed (%d with engine options skipped)", passed, len(corpus.Cases)-skipped, skipped)
}

func TestPredicateSemanticsFixes(test *testing.T) {
	deepExpr := "when 1 < 0 < " + strings.Repeat("[", 49) + "1" + strings.Repeat("]", 49)
	tests := []struct {
		name    string
		cond    string
		ctx     map[string]interface{}
		want    bool
		wantErr bool
	}{
		{
			name:    "nan is truthy in bare truthiness predicate",
			cond:    "when x",
			ctx:     map[string]interface{}{"x": math.NaN()},
			want:    true,
			wantErr: false,
		},
		{
			name:    "chained comparison short circuits on first false without evaluating errored second comparison",
			cond:    deepExpr,
			ctx:     map[string]interface{}{},
			want:    false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		test.Run(tt.name, func(test *testing.T) {
			got, err := EvalCondition(tt.cond, tt.ctx)
			if (err != nil) != tt.wantErr {
				test.Fatalf("EvalCondition(%q) error = %v, wantErr %v", tt.cond, err, tt.wantErr)
			}
			if got != tt.want {
				test.Errorf("EvalCondition(%q) got = %v, want %v", tt.cond, got, tt.want)
			}
		})
	}
}

func readCorpus(test *testing.T, name string, into interface{}) {
	test.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "prismpath", "portable", "conformance", name))
	if err != nil {
		test.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		test.Fatalf("parse %s: %v", name, err)
	}
}

// The frozen canon/2 vectors (spec-verified-core.md sections 3 and 3.2): the strict reader refuses every case
// with the reference's rule (not-canonical for a spelling that is not the canonical one) or accepts it as its
// own canonical bytes, and Canon2Canonicalize gives the reference's canonical bytes, a fixed point, or refuses
// with the same rule.
func TestCanon2Conformance(test *testing.T) {
	var corpus struct {
		Version int `json:"version"`
		Cases   []struct {
			Name         string `json:"name"`
			Hex          string `json:"hex"`
			CanonicalHex string `json:"canonical_hex"`
			Refuse       string `json:"refuse"`
		} `json:"cases"`
	}
	readCorpus(test, "canon2.json", &corpus)
	if corpus.Version != 2 {
		test.Fatalf("canon2.json version %d, want 2", corpus.Version)
	}
	rule := func(err error) string {
		var canonErr *Canon2Error
		if errors.As(err, &canonErr) {
			return canonErr.Rule
		}
		return ""
	}
	passed := 0
	for _, vector := range corpus.Cases {
		input, err := hex.DecodeString(vector.Hex)
		if err != nil {
			test.Fatalf("[%s] bad hex: %v", vector.Name, err)
		}
		document, readErr := Canon2Read(input)
		if vector.Refuse != "" {
			if rule(readErr) != vector.Refuse {
				test.Errorf("[%s] read as %v (%v), the reference refuses it as %s", vector.Name, document, readErr, vector.Refuse)
				continue
			}
		} else {
			if readErr != nil {
				test.Errorf("[%s] refused (%v), the reference reads it", vector.Name, readErr)
				continue
			}
			if written, _ := Canon2Write(document); !bytes.Equal(written, input) {
				test.Errorf("[%s] the strict reader accepted bytes that are not canonical", vector.Name)
				continue
			}
		}
		canonical, canonErr := Canon2Canonicalize(input)
		if vector.CanonicalHex == "" {
			if rule(canonErr) != vector.Refuse {
				test.Errorf("[%s] canonicalized (%v), the reference refuses it as %s", vector.Name, canonErr, vector.Refuse)
				continue
			}
			passed++
			continue
		}
		if canonErr != nil || hex.EncodeToString(canonical) != vector.CanonicalHex {
			test.Errorf("[%s] canonicalized to %x (%v), want %s", vector.Name, canonical, canonErr, vector.CanonicalHex)
			continue
		}
		again, againErr := Canon2Read(canonical)
		rewritten, _ := Canon2Write(again)
		if againErr != nil || !bytes.Equal(rewritten, canonical) {
			test.Errorf("[%s] the canonical bytes are not a fixed point", vector.Name)
			continue
		}
		passed++
	}
	test.Logf("canon2: %d/%d passed", passed, len(corpus.Cases))
}

// Field definitions (SPEC section 4.5), replayed from the frozen vectors the Python reference generates: the
// shared conversion, parse time lowering to the exact text the reference produces, the policy rules in the
// core's order, the canonical boundary and the engine's routes on canonical readings.
func TestFieldDefinitionsConformance(test *testing.T) {
	var corpus struct {
		Conversion []struct {
			Definition string      `json:"definition"`
			Raw        interface{} `json:"raw"`
			Canonical  interface{} `json:"canonical"`
			Refused    string      `json:"refused"`
		} `json:"conversion"`
		Policies []struct {
			Name     string   `json:"name"`
			Flow     string   `json:"flow"`
			Accepted bool     `json:"accepted"`
			Cause    string   `json:"cause"`
			Causes   []string `json:"causes"`
			Lowered  []string `json:"lowered"`
			Probes   []struct {
				Reading map[string]interface{} `json:"reading"`
				Route   string                 `json:"route"`
			} `json:"probes"`
			Refused []struct {
				Reading map[string]interface{} `json:"reading"`
				Field   string                 `json:"field"`
				Reason  string                 `json:"reason"`
			} `json:"refused_readings"`
		} `json:"policies"`
	}
	readCorpus(test, "field_definitions.json", &corpus)
	for _, conversion := range corpus.Conversion {
		definition, err := ParseDefinition("value", conversion.Definition)
		if err != nil {
			test.Errorf("a vector's definition %q does not parse: %v", conversion.Definition, err)
			continue
		}
		value, reason := CanonicalValue(definition, conversion.Raw)
		if conversion.Refused != "" {
			if reason != conversion.Refused {
				test.Errorf("conversion %v of %q: refused as %q (%v), want %q", conversion.Raw, conversion.Definition, reason, value, conversion.Refused)
			}
			continue
		}
		if reason != "" || fmt.Sprint(value) != fmt.Sprint(conversion.Canonical) {
			test.Errorf("conversion %v of %q: got %v (%q), want %v", conversion.Raw, conversion.Definition, value, reason, conversion.Canonical)
		}
	}
	for _, policy := range corpus.Policies {
		graph := Parse(policy.Flow)
		if !policy.Accepted {
			if graph.FieldError == nil || graph.Refused == "" {
				test.Errorf("[%s] parsed although the reference refuses it", policy.Name)
				continue
			}
			causes := []string{}
			for _, found := range graph.FieldError.Problems {
				causes = append(causes, found.Cause)
				if _, registered := CoreCauseCode(found.Cause); !registered {
					test.Errorf("[%s] an unregistered cause %s", policy.Name, found.Cause)
				}
			}
			if graph.FieldError.Cause != policy.Cause || !reflect.DeepEqual(causes, policy.Causes) {
				test.Errorf("[%s] cause %s %v, want %s %v", policy.Name, graph.FieldError.Cause, causes, policy.Cause, policy.Causes)
			}
			for _, edge := range graph.Nodes["s"].Edges {
				if edge.Condition != "never" {
					test.Errorf("[%s] an edge stayed live: %s", policy.Name, edge.Condition)
				}
			}
			if _, err := Run(graph, func(node string, instruction string, state map[string]interface{}) (interface{}, error) {
				return nil, nil
			}, RunOptions{}); err == nil {
				test.Errorf("[%s] the engine ran a refused flow", policy.Name)
			}
			continue
		}
		if graph.FieldError != nil {
			test.Errorf("[%s] refused: %s", policy.Name, graph.FieldError.Message)
			continue
		}
		lowered := []string{}
		for _, edge := range graph.Nodes["s"].Edges {
			lowered = append(lowered, edge.Condition)
		}
		if !reflect.DeepEqual(lowered, policy.Lowered) {
			test.Errorf("[%s] lowered %q, want %q", policy.Name, lowered, policy.Lowered)
		}
		for _, probe := range policy.Probes {
			routed := ""
			for _, edge := range graph.Nodes["s"].Edges {
				if matched, err := EvalCondition(edge.Condition, probe.Reading); err == nil && matched && IsDeterministic(edge.Condition) {
					routed = edge.Target
					break
				}
			}
			if routed != probe.Route {
				test.Errorf("[%s] %v routed to %q, want %q", policy.Name, probe.Reading, routed, probe.Route)
			}
		}
		for _, refused := range policy.Refused {
			field, reason, found := SystemBoundary(graph, refused.Reading)
			if !found || field != refused.Field || reason != refused.Reason {
				test.Errorf("[%s] %v refused as %s %s (%v), want %s %s", policy.Name, refused.Reading, field, reason, found, refused.Field, refused.Reason)
			}
		}
	}
	if Parse("---\nname: t\n---\n## s\n-> e: when x >= 1\n## e\n").FieldError != nil {
		test.Errorf("a flow without definitions was refused")
	}
}

// The system boundary checks every defined field, the policy check only the routed ones (section 6.1).
func TestSystemBoundaryAndPolicyCheck(test *testing.T) {
	graph := Parse("---\nname: t\nstart: s\nfield.x: int min=0 max=10\nfield.unused: bool\nfield.r: fixed scale=100 rounding=floor\n---\n" +
		"## s\n-> hit: when x >= 5 and r >= 0.5\n-> miss: else\n## hit\n## miss\n")
	if graph.FieldError != nil {
		test.Fatalf("refused: %v", graph.FieldError)
	}
	if !reflect.DeepEqual(graph.Routed, []string{"r", "x"}) {
		test.Errorf("routed %v", graph.Routed)
	}
	if field, reason, found := SystemBoundary(graph, map[string]interface{}{"x": int64(5), "r": int64(50)}); !found || field != "unused" || reason != "missing" {
		test.Errorf("system boundary: %s %s %v", field, reason, found)
	}
	if _, _, found := PolicyCheck(graph, map[string]interface{}{"x": int64(5), "r": int64(50)}); found {
		test.Errorf("the policy check refused a reading whose routed fields are canonical")
	}
	if field, reason, found := PolicyCheck(graph, map[string]interface{}{"x": int64(1)}); !found || field != "r" || reason != "missing" {
		test.Errorf("policy check: %s %s %v", field, reason, found)
	}
}

// A decimal threshold is lowered exactly, past the precision of a double, and a refusal carries its cause.
func TestDecimalLoweringIsExact(test *testing.T) {
	graph := Parse("---\nname: t\nstart: s\nfield.d: fixed scale=1000000000 rounding=exact min=0 max=9007199254740991\n---\n" +
		"## s\n-> hit: when d >= 0.007199254\n-> miss: else\n## hit\n## miss\n")
	if got := graph.Nodes["s"].Edges[0].Condition; got != "when d >= 7199254" {
		test.Errorf("lowered %q", got)
	}
	refused := Parse("---\nname: t\nstart: s\nfield.d: fixed scale=100 rounding=exact\n---\n## s\n-> hit: when d >= 0.001\n## hit\n")
	if refused.FieldError == nil || refused.FieldError.Cause != "policy:threshold" || refused.FieldError.Reason != "off-grid" ||
		refused.FieldError.Field != "d" || refused.FieldError.Code != 96 {
		test.Errorf("refusal %+v", refused.FieldError)
	}
}

// `and` and `or` are n-ary, so a long flat chain is one level of depth, and `\xNN` is a code point.
func TestCoreEvaluatorCorrections(test *testing.T) {
	chain := "when " + strings.TrimSuffix(strings.Repeat("x and ", 60), " and ")
	if got, err := EvalCondition(chain, map[string]interface{}{"x": int64(1)}); err != nil || !got {
		test.Errorf("a flat chain of 60 operands: %v %v", got, err)
	}
	if got, err := EvalCondition(`when s == "\x85\xe9"`, map[string]interface{}{"s": "\u0085\u00e9"}); err != nil || !got {
		test.Errorf(`\xNN as a code point: %v %v`, got, err)
	}
}

// Front matter is read with Python's whitespace: U+001F is whitespace, U+FEFF is not.
func TestDefinitionWhitespaceIsPythons(test *testing.T) {
	flow := func(text string) Graph {
		return Parse("---\nname: t\nstart: s\nfield.x: " + text + "\n---\n## s\n-> hit: when x >= 1\n## hit\n")
	}
	if graph := flow("\x1fint\x1f"); graph.FieldError != nil {
		test.Errorf("refused: %v", graph.FieldError)
	}
	for _, text := range []string{"\ufeffint", "\ufeff"} {
		if graph := flow(text); graph.FieldError == nil || graph.FieldError.Reason != "unknown-kind" {
			test.Errorf("%q: %+v", text, graph.FieldError)
		}
	}
}

// Rules sources (a `.rules.md` filename or any `-> refuse|escalate <cause>:` line) are refused with a
// ParseError pointing to `prismpath policy compile`, while rendered code edges (`refuse_106:`), normal edges
// and prose mentioning refuse continue to parse as ordinary flows.
func TestRulesSourceConformance(test *testing.T) {
	var corpus struct {
		Version int `json:"version"`
		Cases   []struct {
			Name     string  `json:"name"`
			Filename *string `json:"filename"`
			Flow     string  `json:"flow"`
			Expect   struct {
				OK         bool              `json:"ok"`
				Start      string            `json:"start"`
				Nodes      [][]interface{}   `json:"nodes"`
				Error      string            `json:"error"`
				ErrorClass string            `json:"error_class"`
			} `json:"expect"`
		} `json:"cases"`
	}
	readCorpus(test, "rules_source.json", &corpus)
	if corpus.Version != 1 {
		test.Fatalf("rules_source.json version %d, want 1", corpus.Version)
	}
	tempRoot := test.TempDir()
	passed := 0
	for idx, tc := range corpus.Cases {
		filename := ""
		if tc.Filename != nil {
			filename = *tc.Filename
		}
		var graph Graph
		if filename != "" {
			graph = ParseNamed(tc.Flow, filename)
		} else {
			graph = Parse(tc.Flow)
		}

		if tc.Expect.Error != "" {
			if graph.ParseError == nil || !graph.ParseError.RulesSource {
				test.Errorf("[%s] parsed although reference refuses it as %s", tc.Name, tc.Expect.ErrorClass)
				continue
			}
			if graph.ParseError.Error() != tc.Expect.Error || graph.Refused != tc.Expect.Error {
				test.Errorf("[%s] error %q (refused=%q), want %q", tc.Name, graph.ParseError.Error(), graph.Refused, tc.Expect.Error)
				continue
			}
			if !strings.Contains(graph.ParseError.Error(), "prismpath policy compile") {
				test.Errorf("[%s] error message does not name prismpath policy compile: %q", tc.Name, graph.ParseError.Error())
				continue
			}
			_, runErr := Run(graph, func(node string, instruction string, state map[string]interface{}) (interface{}, error) {
				return nil, nil
			}, RunOptions{})
			var runParseErr *ParseError
			if !errors.As(runErr, &runParseErr) || !runParseErr.RulesSource {
				test.Errorf("[%s] Run did not return a rules-source ParseError: %v", tc.Name, runErr)
				continue
			}
			if filename != "" {
				filePath := filepath.Join(tempRoot, fmt.Sprintf("case_%d", idx), filepath.FromSlash(filename))
				if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
					test.Fatalf("[%s] mkdir: %v", tc.Name, err)
				}
				if err := os.WriteFile(filePath, []byte(tc.Flow), 0o644); err != nil {
					test.Fatalf("[%s] write: %v", tc.Name, err)
				}
				_, fileErr := ParseFile(filePath)
				var fileParseErr *ParseError
				if !errors.As(fileErr, &fileParseErr) || !fileParseErr.RulesSource || fileParseErr.Error() != tc.Expect.Error {
					test.Errorf("[%s] ParseFile got err=%v, want ParseError(%q)", tc.Name, fileErr, tc.Expect.Error)
					continue
				}
			} else {
				_, chkErr := ParseChecked(tc.Flow)
				var chkParseErr *ParseError
				if !errors.As(chkErr, &chkParseErr) || !chkParseErr.RulesSource || chkParseErr.Error() != tc.Expect.Error {
					test.Errorf("[%s] ParseChecked got err=%v, want ParseError(%q)", tc.Name, chkErr, tc.Expect.Error)
					continue
				}
			}
			passed++
			continue
		}

		if graph.ParseError != nil || graph.Refused != "" {
			test.Errorf("[%s] unexpectedly refused: %q (%v)", tc.Name, graph.Refused, graph.ParseError)
			continue
		}
		if graph.Start != tc.Expect.Start {
			test.Errorf("[%s] start=%q, want %q", tc.Name, graph.Start, tc.Expect.Start)
			continue
		}
		gotNodes := make([][]interface{}, 0, len(graph.NodeOrder))
		for _, nodeName := range graph.NodeOrder {
			edges := make([]interface{}, 0, len(graph.Nodes[nodeName].Edges))
			for _, edge := range graph.Nodes[nodeName].Edges {
				edges = append(edges, []interface{}{edge.Target, edge.Condition})
			}
			gotNodes = append(gotNodes, []interface{}{nodeName, edges})
		}
		if !reflect.DeepEqual(gotNodes, tc.Expect.Nodes) {
			test.Errorf("[%s] nodes=%v, want %v", tc.Name, gotNodes, tc.Expect.Nodes)
			continue
		}
		if filename != "" {
			filePath := filepath.Join(tempRoot, fmt.Sprintf("case_%d", idx), filepath.FromSlash(filename))
			if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
				test.Fatalf("[%s] mkdir: %v", tc.Name, err)
			}
			if err := os.WriteFile(filePath, []byte(tc.Flow), 0o644); err != nil {
				test.Fatalf("[%s] write: %v", tc.Name, err)
			}
			fileGraph, fileErr := ParseFile(filePath)
			if fileErr != nil || fileGraph.Start != tc.Expect.Start {
				test.Errorf("[%s] ParseFile got start=%q err=%v, want %q", tc.Name, fileGraph.Start, fileErr, tc.Expect.Start)
				continue
			}
		} else {
			if _, chkErr := ParseChecked(tc.Flow); chkErr != nil {
				test.Errorf("[%s] ParseChecked unexpectedly refused: %v", tc.Name, chkErr)
				continue
			}
		}
		passed++
	}
	test.Logf("rules_source: %d/%d passed", passed, len(corpus.Cases))
}
