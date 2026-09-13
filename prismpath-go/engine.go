package prismpath

import (
	"fmt"
	"strings"
)

// PendingState carries suspension details.
type PendingState struct {
	Node   string      `json:"node"`
	Reason string      `json:"reason,omitempty"`
	Spawn  interface{} `json:"spawn,omitempty"`
}

// RunResult represents the execution outcome of a flow run.
type RunResult struct {
	Path        []string               `json:"path"`
	Stopped     string                 `json:"stopped"`
	PendingNode *string                `json:"pending_node"`
	Spawn       interface{}            `json:"spawn"`
	State       map[string]interface{} `json:"state"`
}

// RunOptions configures engine execution.
type RunOptions struct {
	MaxSteps int
	Start    string
	State    map[string]interface{}
}

// WorkerFn defines the signature for node worker callables.
type WorkerFn func(node string, instruction string, state map[string]interface{}) (interface{}, error)

// PortabilityViolations checks if graph contains reachable semantic edges.
func PortabilityViolations(graph Graph) []string {
	var violations []string
	for _, nodeName := range graph.NodeOrder {
		flowNode := graph.Nodes[nodeName]
		for _, edge := range flowNode.Edges {
			if IsSemantic(edge.Condition) {
				violations = append(violations, fmt.Sprintf("%s -> %s: %s", flowNode.Name, edge.Target, edge.Condition))
			}
		}
	}
	return violations
}

// pyStr renders a worker outcome the way Python's str() does — the coercion the
// routing predicates see. Differential fuzzing showed String() diverges on
// exactly the values that then route differently: true -> "True", null -> "None",
// [1,2] -> "[1, 2]". Numbers stay as Go renders them (cross-language ambiguous).
func pyStr(value interface{}) string {
	switch typedValue := value.(type) {
	case nil:
		return "None"
	case bool:
		if typedValue {
			return "True"
		}
		return "False"
	case string:
		return typedValue
	case []interface{}:
		parts := make([]string, len(typedValue))
		for index, element := range typedValue {
			parts[index] = pyRepr(element)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]interface{}:
		parts := make([]string, 0, len(typedValue))
		for key, val := range typedValue {
			parts = append(parts, "'"+key+"': "+pyRepr(val))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	default:
		return fmt.Sprint(value)
	}
}

func pyRepr(value interface{}) string {
	if text, ok := value.(string); ok {
		return "'" + text + "'"
	}
	return pyStr(value)
}

// Run executes a P0 portable flow graph against a worker function.
func Run(graph Graph, worker WorkerFn, opts RunOptions) (RunResult, error) {
	if violations := PortabilityViolations(graph); len(violations) > 0 {
		return RunResult{}, fmt.Errorf("non-portable flow: contains semantic edges: %s", strings.Join(violations, "; "))
	}

	maxSteps := opts.MaxSteps
	if maxSteps <= 0 {
		maxSteps = 25
	}

	startNode := opts.Start
	if startNode == "" {
		startNode = graph.Start
	}

	state := opts.State
	if state == nil {
		state = make(map[string]interface{})
	}

	visits := make(map[string]int)
	if vMap, ok := state["visits"].(map[string]int); ok {
		visits = vMap
	} else {
		state["visits"] = visits
	}

	outcomes := make(map[string]interface{})
	state["_outcomes"] = outcomes

	errorCounts := make(map[string]int)
	state["_errors"] = errorCounts

	curr := startNode
	path := []string{}
	if curr != "" {
		path = append(path, curr)
	}
	var pendingNode *string
	var spawnVal interface{}
	stopped := ""

	for step := 0; step < maxSteps; step++ {
		flowNode, exists := graph.Nodes[curr]
		if !exists {
			stopped = "stuck"
			break
		}

		if len(flowNode.Edges) == 0 {
			stopped = "terminal"
			break
		}

		visits[curr]++

		// Invoke worker
		workerRes, workerErr := worker(curr, flowNode.Instruction, state)

		// Error tier: a worker error routes on `on error` edges only, with a
		// minimal error context (per-node error_count, visits).
		if workerErr != nil {
			errorCounts[curr]++
			errCtx := map[string]interface{}{
				"error":         true,
				"error_type":    "Error",
				"error_message": workerErr.Error(),
				"error_count":   errorCounts[curr],
				"visits":        visits[curr],
			}
			matched := false
			for _, edge := range flowNode.Edges {
				if !IsError(edge.Condition) {
					continue
				}
				errExp := ErrorExpr(edge.Condition)
				if errExp == "" {
					curr = edge.Target
					matched = true
					break
				}
				ok, evalErr := EvalCondition(errExp, errCtx)
				if evalErr == nil && ok {
					curr = edge.Target
					matched = true
					break
				}
			}
			if !matched {
				return RunResult{}, workerErr // no handler -> propagate
			}
			path = append(path, curr)
			continue
		}

		// Normalize the outcome to (text, fields). The routing context is the
		// outcome's own fields plus visits — never carried across nodes.
		var outcomeDict map[string]interface{}
		ctx := make(map[string]interface{})
		switch workerValue := workerRes.(type) {
		case map[string]interface{}:
			outcomeDict = workerValue
			for key, val := range workerValue {
				ctx[key] = val
			}
		case string:
			outcomeDict = map[string]interface{}{"text": workerValue}
			ctx["text"] = workerValue
		default:
			text := pyStr(workerValue)
			outcomeDict = map[string]interface{}{"text": text}
			ctx["text"] = text
		}
		ctx["visits"] = visits[curr]
		outcomes[curr] = outcomeDict

		// Human handoff
		if needsHuman, ok := outcomeDict["needs_human"].(bool); ok && needsHuman {
			stopped = "needs_human"
			pNode := curr
			pendingNode = &pNode
			break
		}

		// Fan-out / wait suspension
		if spawnRequest, ok := outcomeDict["spawn"]; ok && spawnRequest != nil {
			stopped = "waiting"
			pNode := curr
			pendingNode = &pNode
			spawnVal = spawnRequest
			break
		}
		if waitFlag, ok := outcomeDict["wait"].(bool); ok && waitFlag {
			stopped = "waiting"
			pNode := curr
			pendingNode = &pNode
			break
		}

		// Deterministic edges in document order
		matched := false
		for _, edge := range flowNode.Edges {
			if IsDeterministic(edge.Condition) {
				match, evalErr := EvalCondition(edge.Condition, ctx)
				if evalErr == nil && match {
					curr = edge.Target
					matched = true
					break
				}
			}
		}
		if matched {
			path = append(path, curr)
			continue
		}

		stopped = "stuck"
		break
	}

	if stopped == "" {
		stopped = "max_steps"
	}

	return RunResult{
		Path:        path,
		Stopped:     stopped,
		PendingNode: pendingNode,
		Spawn:       spawnVal,
		State:       state,
	}, nil
}
