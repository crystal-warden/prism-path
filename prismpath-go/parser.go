package prismpath

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Edge represents a flow edge.
type Edge struct {
	Target    string `json:"target"`
	Condition string `json:"condition"`
}

// Annotation represents a node annotation.
type Annotation struct {
	Name string                 `json:"name"`
	Args map[string]interface{} `json:"args"`
}

// Node represents a graph node.
type Node struct {
	Name        string       `json:"name"`
	Instruction string       `json:"instruction"`
	Edges       []Edge       `json:"edges"`
	Annotations []Annotation `json:"annotations"`
}

// Graph represents a parsed Markdown flow graph.
type Graph struct {
	Name      string          `json:"name"`
	Start     string          `json:"start"`
	Nodes     map[string]Node `json:"nodes"`
	NodeOrder []string        `json:"node_order"`
	Terminals []string        `json:"terminals"`
}

var (
	nodeHeadingRe = regexp.MustCompile(`^\s*##\s+(.+?)\s*$`)
	edgeRe        = regexp.MustCompile(`^\s*-?\s*->\s*([A-Za-z0-9_\-]+)\s*:\s*(.+?)\s*$`)
	annotationRe  = regexp.MustCompile(`^\s*@(\w+)\s*\((.*)\)\s*$`)
)

func splitLines(src string) []string {
	var lines []string
	var sb strings.Builder
	for i := 0; i < len(src); {
		r, size := utf8DecodeRune(src[i:])
		if r == '\r' {
			if i+size < len(src) && src[i+size] == '\n' {
				lines = append(lines, sb.String())
				sb.Reset()
				i += size + 1
				continue
			}
			lines = append(lines, sb.String())
			sb.Reset()
			i += size
			continue
		}
		if r == '\n' || r == '\v' || r == '\f' || r == 0x85 || r == 0x2028 || r == 0x2029 || (r >= 0x1c && r <= 0x1e) {
			lines = append(lines, sb.String())
			sb.Reset()
			i += size
			continue
		}
		sb.WriteRune(r)
		i += size
	}
	lines = append(lines, sb.String())
	return lines
}

func utf8DecodeRune(s string) (rune, int) {
	r, size := utf8.DecodeRuneInString(s)
	return r, size
}

// Parse parses a Markdown flow document into a Graph.
func Parse(markdown string) Graph {
	lines := splitLines(markdown)
	var name string
	var start string

	inFrontmatter := false
	fmDone := false
	bodyLines := []string{}

	if len(lines) > 0 && strings.TrimSpace(lines[0]) == "---" {
		inFrontmatter = true
		for i := 1; i < len(lines); i++ {
			line := lines[i]
			if strings.TrimSpace(line) == "---" {
				fmDone = true
				bodyLines = lines[i+1:]
				break
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v := strings.TrimSpace(parts[1])
				if k == "name" {
					name = v
				} else if k == "start" {
					start = v
				}
			}
		}
	}

	if !inFrontmatter || !fmDone {
		bodyLines = lines
	}

	if name == "" {
		name = "flow"
	}

	nodes := make(map[string]Node)
	nodeOrder := []string{}
	var currNode *Node
	currInstLines := []string{}

	flushNode := func() {
		if currNode != nil {
			currNode.Instruction = strings.TrimSpace(strings.Join(currInstLines, "\n"))
			nodes[currNode.Name] = *currNode
		}
	}

	for _, line := range bodyLines {
		if m := nodeHeadingRe.FindStringSubmatch(line); len(m) > 1 {
			flushNode()
			normName := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(m[1])), " ", "_")
			if _, exists := nodes[normName]; !exists {
				nodeOrder = append(nodeOrder, normName)
			}
			currNode = &Node{
				Name:        normName,
				Edges:       []Edge{},
				Annotations: []Annotation{},
			}
			currInstLines = []string{}
			continue
		}

		if currNode != nil {
			if m := edgeRe.FindStringSubmatch(line); len(m) > 2 {
				currNode.Edges = append(currNode.Edges, Edge{
					Target:    strings.TrimSpace(m[1]),
					Condition: strings.TrimSpace(m[2]),
				})
				continue
			}
			if m := annotationRe.FindStringSubmatch(line); len(m) > 2 {
				currNode.Annotations = append(currNode.Annotations, Annotation{
					Name: strings.TrimSpace(m[1]),
					Args: map[string]interface{}{},
				})
				continue
			}
			currInstLines = append(currInstLines, line)
		}
	}
	flushNode()

	if start == "" && len(nodeOrder) > 0 {
		start = nodeOrder[0]
	}

	terminals := []string{}
	for _, n := range nodeOrder {
		if len(nodes[n].Edges) == 0 {
			terminals = append(terminals, n)
		}
	}

	return Graph{
		Name:      name,
		Start:     start,
		Nodes:     nodes,
		NodeOrder: nodeOrder,
		Terminals: terminals,
	}
}
