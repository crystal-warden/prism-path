package prismpath

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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

func TestPredicatesConformance(t *testing.T) {
	path := filepath.Join("..", "prismpath", "portable", "conformance", "predicates.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read predicates.json: %v", err)
	}

	var corpus predicatesCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatalf("failed to unmarshal predicates.json: %v", err)
	}

	passed := 0
	for _, c := range corpus.Cases {
		got, err := EvalCondition(c.Cond, c.Ctx)
		var gotResult interface{}
		if err != nil {
			gotResult = "ERROR"
		} else {
			gotResult = got
		}

		if reflect.DeepEqual(gotResult, c.Expect) {
			passed++
		} else {
			t.Errorf("PRED MISMATCH cond=%q ctx=%v\n  expect=%v got=%v", c.Cond, c.Ctx, c.Expect, gotResult)
		}
	}

	t.Logf("predicates: %d/%d passed", passed, len(corpus.Cases))
}

func TestFlowsConformance(t *testing.T) {
	path := filepath.Join("..", "prismpath", "portable", "conformance", "flows.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read flows.json: %v", err)
	}

	var corpus flowsCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatalf("failed to unmarshal flows.json: %v", err)
	}

	passed := 0
	for _, fx := range corpus.Cases {
		g := Parse(fx.Flow)
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

			if m, ok := outcome.(map[string]interface{}); ok {
				if rMsg, ok := m["__raise__"].(string); ok {
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

		res, err := Run(g, scriptedWorker, opts)
		if err != nil {
			t.Errorf("FLOW ERROR %s: %v", fx.Name, err)
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
			t.Errorf("FLOW MISMATCH %s\n  expect path=%v stopped=%v pending=%v spawn=%v\n  got    path=%v stopped=%v pending=%v spawn=%v",
				fx.Name, fx.Expect.Path, fx.Expect.Stopped, expectedPending, fx.Expect.Spawn,
				res.Path, res.Stopped, res.PendingNode, res.Spawn)
		}
	}

	t.Logf("flows: %d/%d passed", passed, len(corpus.Cases))
}
