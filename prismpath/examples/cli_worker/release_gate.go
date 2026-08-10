// Release-gate worker (Go). Read the from/to versions from the [context] block on stdin, compute the
// semver bump and whether it is breaking, print ONE JSON object, exit 0. A nonzero exit routes to the
// flow's error tier.
// Build once (go build -o release_gate release_gate.go), then wire it in with:
//   cli_agent(["./release_gate"], pass_state=["from", "to"])
package main

import (
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
)

func semver(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func main() {
	raw, _ := io.ReadAll(os.Stdin)
	_, after, _ := strings.Cut(string(raw), "[context]") // PrismPath appends: ...\n\n[context]\n{json}
	var c struct{ From, To string }
	if err := json.Unmarshal([]byte(strings.TrimSpace(after)), &c); err != nil || c.From == "" || c.To == "" {
		os.Stderr.WriteString("missing from/to versions") // -> the flow's error tier
		os.Exit(1)
	}
	a, ok1 := semver(c.From)
	b, ok2 := semver(c.To)
	if !ok1 || !ok2 {
		os.Stderr.WriteString("unparseable version")
		os.Exit(1)
	}
	bump := "none"
	switch {
	case b[0] != a[0]:
		bump = "major"
	case b[1] != a[1]:
		bump = "minor"
	case b[2] != a[2]:
		bump = "patch"
	}
	out, _ := json.Marshal(map[string]interface{}{"bump": bump, "breaking": bump == "major"})
	os.Stdout.Write(out)
}
