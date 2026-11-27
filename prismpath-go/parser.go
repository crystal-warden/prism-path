package prismpath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RulesSuffix is the filename suffix of a rules source rather than a workflow document.
const RulesSuffix = ".rules.md"

// ParseError reports why a flow document could not be parsed. RulesSource is true when the document
// is a rules source rather than a flow (Python's RulesSourceError, a subclass of ParseError).
type ParseError struct {
	Message     string
	RulesSource bool
}

func (parseErr *ParseError) Error() string {
	return parseErr.Message
}

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
	// Fields are the field definitions of SPEC section 4.5, by name; empty for a flow that defines none.
	Fields map[string]FieldDefinition `json:"fields,omitempty"`
	// Routed are the defined fields some deterministic edge reads, in code point order.
	Routed []string `json:"routed,omitempty"`
	// Refused says why this kernel will not run the flow: its field definitions or the conditions that read
	// them break a rule of the verified core (docs/design/spec-verified-core.md section 4). A refused flow
	// has every edge disabled and Run refuses it; FieldError names the first problem, with its registered
	// cause, and every other problem in the core's order.
	Refused    string                `json:"refused,omitempty"`
	ParseError *ParseError           `json:"-"`
	FieldError *FieldDefinitionError `json:"-"`
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

func isPySpace(char rune) bool {
	return unicode.IsSpace(char) || char == 0x85 || (char >= 0x1c && char <= 0x1f)
}

// matchRulesLine reports whether line is a rule of a rules source (`-> refuse <cause>:` or
// `-> escalate <cause>:`), matching Python's RULES_LINE_RE.
func matchRulesLine(line string) bool {
	runes := []rune(line)
	pos := 0
	for pos < len(runes) && isPySpace(runes[pos]) {
		pos++
	}
	if pos < len(runes) && runes[pos] == '-' && !(pos+1 < len(runes) && runes[pos+1] == '>') {
		pos++
		for pos < len(runes) && isPySpace(runes[pos]) {
			pos++
		}
	}
	if !(pos+1 < len(runes) && runes[pos] == '-' && runes[pos+1] == '>') {
		return false
	}
	pos += 2
	for pos < len(runes) && isPySpace(runes[pos]) {
		pos++
	}
	rest := string(runes[pos:])
	var tail string
	switch {
	case strings.HasPrefix(rest, "refuse"):
		tail = rest[len("refuse"):]
	case strings.HasPrefix(rest, "escalate"):
		tail = rest[len("escalate"):]
	default:
		return false
	}
	tailRunes := []rune(tail)
	tpos := 0
	for tpos < len(tailRunes) && isPySpace(tailRunes[tpos]) {
		tpos++
	}
	if tpos == 0 {
		return false
	}
	tokStart := tpos
	for tpos < len(tailRunes) && !isPySpace(tailRunes[tpos]) {
		tpos++
	}
	return tpos-tokStart >= 2 && tailRunes[tpos-1] == ':'
}

func rulesSourceLineMessage(lineNumber int) string {
	return fmt.Sprintf(
		"line %d is a rule of a rules source, not a flow edge. A rules source is compiled with "+
			"`prismpath policy compile` and read back with `prismpath policy render`",
		lineNumber,
	)
}

func rulesSourceFileMessage(basename string) string {
	return fmt.Sprintf(
		"%s is a rules source, not a flow. A rules source is compiled with "+
			"`prismpath policy compile` and read back with `prismpath policy render`",
		basename,
	)
}

func refusedRulesSource(message string) Graph {
	return Graph{
		Nodes:      map[string]Node{},
		NodeOrder:  []string{},
		Terminals:  []string{},
		Refused:    message,
		ParseError: &ParseError{Message: message, RulesSource: true},
	}
}

func basenameOf(path string) string {
	idx := strings.LastIndexAny(path, `/\`)
	if idx >= 0 {
		return path[idx+1:]
	}
	return path
}

// Parse parses a Markdown flow document into a Graph.
func Parse(markdown string) Graph {
	lines := splitLines(markdown)
	var name string
	var start string

	inFrontmatter := false
	fmDone := false
	meta := map[string]string{}
	bodyLines := []string{}
	bodyOffset := 0

	if len(lines) > 0 && pyTrim(lines[0]) == "---" {
		inFrontmatter = true
		for lineIndex := 1; lineIndex < len(lines); lineIndex++ {
			line := lines[lineIndex]
			if pyTrim(line) == "---" {
				fmDone = true
				bodyLines = lines[lineIndex+1:]
				bodyOffset = lineIndex + 1
				break
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := pyTrim(parts[0])
				value := pyTrim(parts[1])
				meta[key] = value
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
		bodyOffset = 0
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

	for idx, line := range bodyLines {
		if matchRulesLine(line) {
			return refusedRulesSource(rulesSourceLineMessage(bodyOffset + idx + 1))
		}
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

	graph := Graph{
		Name:      name,
		Start:     start,
		Nodes:     nodes,
		NodeOrder: nodeOrder,
		Terminals: terminals,
	}
	// A flow that defines its fields is checked in the verified core's order and its decimal thresholds are
	// lowered to canonical integers here, as the reference does (the front matter closed, as the reference
	// reads it only then); a flow that breaks a rule is refused with a cause and every edge disabled.
	if fmDone {
		applyDefinitions(&graph, meta)
	}
	return graph
}

// ParseNamed parses a Markdown flow document, also refusing a filename ending in `.rules.md`.
func ParseNamed(markdown string, filename string) Graph {
	if filename != "" {
		base := basenameOf(filename)
		if strings.HasSuffix(base, RulesSuffix) {
			return refusedRulesSource(rulesSourceFileMessage(base))
		}
	}
	return Parse(markdown)
}

// ParseChecked parses a Markdown flow document, returning a ParseError or FieldDefinitionError on refusal.
func ParseChecked(markdown string) (Graph, error) {
	graph := Parse(markdown)
	if graph.ParseError != nil {
		return Graph{}, graph.ParseError
	}
	if graph.FieldError != nil {
		return Graph{}, graph.FieldError
	}
	if graph.Refused != "" {
		return Graph{}, errors.New(graph.Refused)
	}
	return graph, nil
}

// ParseFile reads and parses a flow file on disk, refusing `.rules.md` rules sources before parsing.
func ParseFile(path string) (Graph, error) {
	base := filepath.Base(path)
	if strings.HasSuffix(base, RulesSuffix) {
		return Graph{}, &ParseError{Message: rulesSourceFileMessage(base), RulesSource: true}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Graph{}, err
	}
	return ParseChecked(string(raw))
}
