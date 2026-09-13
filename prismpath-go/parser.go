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
	for pos := 0; pos < len(src); {
		char, size := utf8DecodeRune(src[pos:])
		if char == '\r' {
			if pos+size < len(src) && src[pos+size] == '\n' {
				lines = append(lines, sb.String())
				sb.Reset()
				pos += size + 1
				continue
			}
			lines = append(lines, sb.String())
			sb.Reset()
			pos += size
			continue
		}
		if char == '\n' || char == '\v' || char == '\f' || char == 0x85 || char == 0x2028 || char == 0x2029 || (char >= 0x1c && char <= 0x1e) {
			lines = append(lines, sb.String())
			sb.Reset()
			pos += size
			continue
		}
		sb.WriteRune(char)
		pos += size
	}
	lines = append(lines, sb.String())
	return lines
}

func utf8DecodeRune(text string) (rune, int) {
	char, size := utf8.DecodeRuneInString(text)
	return char, size
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
		for lineIndex := 1; lineIndex < len(lines); lineIndex++ {
			line := lines[lineIndex]
			if strings.TrimSpace(line) == "---" {
				fmDone = true
				bodyLines = lines[lineIndex+1:]
				break
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				if key == "name" {
					name = value
				} else if key == "start" {
					start = value
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
		if match := nodeHeadingRe.FindStringSubmatch(line); len(match) > 1 {
			flushNode()
			normName := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(match[1])), " ", "_")
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
			if match := edgeRe.FindStringSubmatch(line); len(match) > 2 {
				currNode.Edges = append(currNode.Edges, Edge{
					Target:    strings.TrimSpace(match[1]),
					Condition: strings.TrimSpace(match[2]),
				})
				continue
			}
			if match := annotationRe.FindStringSubmatch(line); len(match) > 2 {
				currNode.Annotations = append(currNode.Annotations, Annotation{
					Name: strings.TrimSpace(match[1]),
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
	for _, nodeName := range nodeOrder {
		if len(nodes[nodeName].Edges) == 0 {
			terminals = append(terminals, nodeName)
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
