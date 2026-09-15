package prismpath

import (
	"encoding/json"
	"errors"
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
	for _, fx := range corpus.Cases {
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

	test.Logf("flows: %d/%d passed", passed, len(corpus.Cases))
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
