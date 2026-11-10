// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC

// Command core_diff is the Go leg of the verified core's differential harness (formal/diff/core_diff.py).
// An adapter, not part of the kernel: it composes the kernel's own exported functions (Parse,
// IsDeterministic, EvalCondition, in the engine's first deterministic match) and prints what they decide.
// The kernel does not implement field definitions (SPEC section 4.5) and refuses every flow that defines
// its fields (spec-verified-core.md D5); it has no canon/2 reader, so a reading is read with
// encoding/json after a UTF-8 check, and a difference that is only a canon/2 rule is a reader gap.
//
// Input on stdin: `case <id> <n>\n`, then the policy image, the flow text and n readings, each framed as
// `<byte length>\n<bytes>\n`. A flow of length 0 means the image has no flow rendering. Output: one JSON
// line per case.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

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

func readingVerdict(graph prismpath.Graph, data []byte) map[string]interface{} {
	if !utf8.Valid(data) {
		return map[string]interface{}{"verdict": "refuse", "cause": "reading:unreadable", "reason": "utf8"}
	}
	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return map[string]interface{}{"verdict": "refuse", "cause": "reading:unreadable", "reason": "syntax"}
	}
	object, ok := doc.(map[string]interface{})
	if !ok {
		return map[string]interface{}{"verdict": "refuse", "cause": "reading:not-object"}
	}
	target, matched := firstDeterministic(graph.Nodes[graph.Start].Edges, object)
	if !matched {
		return map[string]interface{}{"verdict": "refuse", "cause": "route:no-matching-edge"}
	}
	return map[string]interface{}{"verdict": "route", "target": target}
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
		r.frame() // the image: this kernel reads flows, not images
		flow := r.frame()
		readings := make([][]byte, count)
		for index := range readings {
			readings[index] = r.frame()
		}
		row := map[string]interface{}{"id": header[1]}
		switch {
		case len(flow) == 0:
			row["policy"] = "unrenderable"
		default:
			graph := prismpath.Parse(string(flow))
			if graph.Refused != "" {
				row["policy"] = "refused"
				row["cause"] = "refusing-kernel"
				row["reason"] = graph.Refused
			} else if _, ok := graph.Nodes[graph.Start]; !ok {
				row["policy"] = "refused"
				row["cause"] = nil
				row["reason"] = "no start node"
			} else {
				verdicts := make([]interface{}, len(readings))
				for index, data := range readings {
					verdicts[index] = readingVerdict(graph, data)
				}
				row["policy"] = "accepted"
				row["defines"] = false
				row["readings"] = verdicts
			}
		}
		line, _ := json.Marshal(row)
		out.Write(line)
		out.WriteString("\n")
	}
}
