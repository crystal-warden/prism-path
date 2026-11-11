// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC

// Command canon2_diff is the Go leg of the canon/2 differential (formal/diff/canon2_diff.py). An adapter,
// not part of the kernel: it reads framed documents on stdin, each `<byte length>\n<bytes>\n`, and prints one
// line per document, `<strict> ; <canonicalize>`: Canon2Read's answer (`ok <hex>` with Canon2Write of the
// value, or `refuse <rule>`) and Canon2Canonicalize's (`canon <hex>` or `refuse <rule>`), or `panic`.
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
	strict := ""
	if value, err := prismpath.Canon2Read(doc); err != nil {
		strict = "refuse " + rule(err)
	} else if out, err := prismpath.Canon2Write(value); err != nil {
		strict = "refuse " + rule(err)
	} else {
		strict = "ok " + hex.EncodeToString(out)
	}
	canon := ""
	if out, err := prismpath.Canon2Canonicalize(doc); err != nil {
		canon = "refuse " + rule(err)
	} else {
		canon = "canon " + hex.EncodeToString(out)
	}
	return strict + " ; " + canon
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
