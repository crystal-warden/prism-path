# prismpath-go — Go portable kernel for PrismPath

`prismpath-go` is a dependency-free Go implementation of the **PrismPath P0 Portable Kernel**. It allows high-performance Go applications, microservices, and network edge appliances to parse and execute Markdown agent workflows without machine learning runtime dependencies.

## Features

- **Zero Dependencies**: Standard library Go only (`go 1.21+`).
- **Data-Not-Code Workflows**: Parse Markdown workflows directly into executable graph data.
- **Safe Predicate Sandbox**: Evaluates `when` AST expressions without `eval` or arbitrary code execution.
- **Durable Suspension**: Supports `needs_human` and `wait`/`spawn` event-driven suspensions.
- **Spec-Conformant**: Built and verified against the frozen PrismPath conformance test vectors (`1079/1079` predicates, `27/27` flows).

## Quickstart

```go
package main

import (
	"fmt"
	"github.com/crystal-warden/prism-path/prismpath-go"
)

func main() {
	flowMd := `
---
name: support_triage
start: classify
---

## classify
Read the support ticket.
-> page_oncall: when category == "outage"
-> queue: when category == "routine"
-> general: else

## page_oncall
Page on-call engineer.

## queue
Queue for morning review.

## general
General help desk.
`

	graph := prismpath.Parse(flowMd)

	// Define node worker
	worker := func(node string, instruction string, state map[string]interface{}) (interface{}, error) {
		if node == "classify" {
			return map[string]interface{}{"category": "outage"}, nil
		}
		return map[string]interface{}{"text": node}, nil
	}

	res, err := prismpath.Run(graph, worker, prismpath.RunOptions{})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Path: %v | Stopped: %s\n", res.Path, res.Stopped)
	// Output: Path: [classify page_oncall] | Stopped: terminal
}
```

## Testing

```bash
go test -v ./...
```
