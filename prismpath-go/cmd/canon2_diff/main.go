// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC

// Command canon2_diff is the Go leg of the canon/2 differential (formal/diff/canon2_diff.py). An adapter,
// not part of the kernel: it reads framed documents on stdin, each `<byte length>\n<bytes>\n`, and prints one
// line per document, `ok <c> <hex>` (Canon2Read accepts it; <hex> is Canon2Write of its value, <c> is 1 when
// the input is already those bytes), `refuse <rule>`, `writefail <rule>` or `panic`.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	prismpath "github.com/crystal-warden/prism-path/prismpath-go"
)

func rule(err error) string {
	var canonErr *prismpath.Canon2Error
	if errors.As(err, &canonErr) {
		return canonErr.Rule
	}
	return "other"
}

func line(doc []byte) (text string) {
	defer func() {
		if recover() != nil {
			text = "panic"
		}
	}()
	value, err := prismpath.Canon2Read(doc)
	if err != nil {
		return "refuse " + rule(err)
	}
	out, err := prismpath.Canon2Write(value)
	if err != nil {
		return "writefail " + rule(err)
	}
	same := 0
	if bytes.Equal(out, doc) {
		same = 1
	}
	return fmt.Sprintf("ok %d %s", same, hex.EncodeToString(out))
}

func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(2)
	}
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	pos := 0
	for pos < len(input) {
		nl := bytes.IndexByte(input[pos:], '\n')
		if nl < 0 {
			os.Exit(2)
		}
		n, err := strconv.Atoi(string(input[pos : pos+nl]))
		if err != nil {
			os.Exit(2)
		}
		start := pos + nl + 1
		if start+n+1 > len(input) {
			os.Exit(2)
		}
		fmt.Fprintln(out, line(input[start:start+n]))
		pos = start + n + 1
	}
}
