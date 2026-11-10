// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC

// Command core_diff is the Go leg of the verified core's differential harness (formal/diff/core_diff.py).
// An adapter, not part of the kernel: it composes the kernel's own exported functions (Canon2Read, Parse,
// SystemBoundary, IsDeterministic, EvalCondition in the engine's first deterministic match, PolicyCheck)
// exactly as the Python leg composes the reference and the Rust leg its port, and prints what they decide.
// The kernel implements the core: canon/2 documents, the field definitions of SPEC section 4.5 with exact
// decimal lowering, the policy rules in the core's order, the system boundary and the policy check
// (docs/design/spec-verified-core.md). Every refusal carries its registered cause and code.
//
// Input on stdin: `case <id> <n>\n`, then the policy image, the flow text and n readings, each framed as
// `<byte length>\n<bytes>\n`. The image and the readings are canon/2 documents; the flow is the image's
// rendering, which the harness writes. A flow of length 0 means the image has no flow rendering. Output: one
// JSON line per case.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	prismpath "github.com/crystal-warden/prism-path/prismpath-go"
)

type reader struct {
	input []byte
	pos   int
}

func (r *reader) line() string {
	end := bytes.IndexByte(r.input[r.pos:], '\n')
	if end < 0 {
		panic("truncated frame header")
	}
	text := string(r.input[r.pos : r.pos+end])
	r.pos += end + 1
	return text
}

func (r *reader) frame() []byte {
	length, err := strconv.Atoi(r.line())
	if err != nil {
		panic(err)
	}
	data := r.input[r.pos : r.pos+length]
	r.pos += length + 1
	return data
}

// firstDeterministic is the engine's deterministic tier: the first deterministic edge whose condition
// holds; an edge whose condition raises does not match.
func firstDeterministic(edges []prismpath.Edge, ctx map[string]interface{}) (string, bool) {
	for _, edge := range edges {
		if !prismpath.IsDeterministic(edge.Condition) {
			continue
		}
		matched, err := prismpath.EvalCondition(edge.Condition, ctx)
		if err == nil && matched {
			return edge.Target, true
		}
	}
	return "", false
}

// refuse is a refusal with its registered code, as the oracle prints one.
func refuse(cause string, detail map[string]interface{}) map[string]interface{} {
	code, _ := prismpath.CoreCauseCode(cause)
	verdict := map[string]interface{}{"verdict": "refuse", "cause": cause, "code": code}
	for key, value := range detail {
		verdict[key] = value
	}
	return verdict
}

func readingVerdict(graph prismpath.Graph, data []byte) map[string]interface{} {
	doc, err := prismpath.Canon2Read(data)
	if err != nil {
		var canonErr *prismpath.Canon2Error
		if errors.As(err, &canonErr) {
			return refuse("reading:unreadable", map[string]interface{}{"reason": canonErr.Rule})
		}
		return map[string]interface{}{"verdict": "refuse", "cause": "crash", "reason": err.Error()}
	}
	object, ok := doc.(map[string]interface{})
	if !ok {
		return refuse("reading:not-object", nil)
	}
	var verdict map[string]interface{}
	if field, reason, refused := prismpath.SystemBoundary(graph, object); refused {
		verdict = refuse("route:contract-violation", map[string]interface{}{"field": field, "reason": reason})
	} else if target, matched := firstDeterministic(graph.Nodes[graph.Start].Edges, object); matched {
		verdict = map[string]interface{}{"verdict": "route", "target": target}
	} else {
		verdict = refuse("route:no-matching-edge", nil)
	}
	if field, reason, refused := prismpath.PolicyCheck(graph, object); refused {
		verdict["policy_check"] = map[string]interface{}{"field": field, "reason": reason}
	} else {
		verdict["policy_check"] = "pass"
	}
	return verdict
}

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	r := &reader{input: input}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for r.pos < len(r.input) {
		header := strings.Split(r.line(), " ")
		if len(header) != 3 || header[0] != "case" {
			panic(fmt.Sprintf("malformed case header %q", header))
		}
		count, _ := strconv.Atoi(header[2])
		image := r.frame()
		flow := r.frame()
		readings := make([][]byte, count)
		for index := range readings {
			readings[index] = r.frame()
		}
		row := map[string]interface{}{"id": header[1]}
		if _, err := prismpath.Canon2Read(image); err != nil {
			var canonErr *prismpath.Canon2Error
			if !errors.As(err, &canonErr) {
				panic(err)
			}
			code, _ := prismpath.CoreCauseCode("policy:unreadable")
			row["policy"], row["cause"], row["reason"], row["code"] = "refused", "policy:unreadable", canonErr.Rule, code
			row["causes"] = []string{"policy:unreadable"}
		} else if len(flow) == 0 {
			row["policy"] = "unrenderable"
		} else {
			graph := prismpath.Parse(string(flow))
			if graph.FieldError != nil {
				reason := graph.Refused
				if len(reason) > 300 {
					reason = reason[:300]
				}
				row["policy"], row["reason"], row["cause"], row["code"] = "refused", reason, graph.FieldError.Cause, graph.FieldError.Code
				row["field"], row["policy_reason"] = nilIfEmpty(graph.FieldError.Field), nilIfEmpty(graph.FieldError.Reason)
				causes := make([]string, len(graph.FieldError.Problems))
				for index, found := range graph.FieldError.Problems {
					causes[index] = found.Cause
				}
				row["causes"] = causes
			} else if _, ok := graph.Nodes[graph.Start]; !ok {
				row["policy"] = "crash: no start node"
			} else {
				verdicts := make([]interface{}, len(readings))
				for index, data := range readings {
					verdicts[index] = readingVerdict(graph, data)
				}
				row["policy"] = "accepted"
				row["defines"] = len(graph.Fields) > 0
				row["readings"] = verdicts
			}
		}
		line, _ := json.Marshal(row)
		out.Write(line)
		out.WriteString("\n")
	}
}

// nilIfEmpty is JSON null for a refusal that names no field or reason.
func nilIfEmpty(text string) interface{} {
	if text == "" {
		return nil
	}
	return text
}
