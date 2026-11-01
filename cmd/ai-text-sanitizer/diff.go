package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/iSerter/go-ai-text-sanitizer/aisanitizer"
)

// writeUnifiedDiff writes a unified line diff (3 lines of context) between a
// and b. Invisible characters are rendered visibly with aisanitizer.Reveal.
func writeUnifiedDiff(w io.Writer, name, a, b string) {
	al, bl := splitLines(a), splitLines(b)
	ops := diffLines(al, bl)
	fmt.Fprintf(w, "--- a/%s\n+++ b/%s\n", name, name)

	const context = 3
	for i := 0; i < len(ops); {
		// Find the next change.
		for i < len(ops) && ops[i].kind == ' ' {
			i++
		}
		if i == len(ops) {
			break
		}
		start := max(i-context, 0)
		end := i
		for end < len(ops) {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			// Stop when more than 2*context unchanged lines follow.
			run := end
			for run < len(ops) && ops[run].kind == ' ' {
				run++
			}
			if run == len(ops) || run-end > 2*context {
				end = min(end+context, len(ops))
				break
			}
			end = run
		}
		hunk := ops[start:end]
		aStart, bStart := ops[start].ai+1, ops[start].bi+1
		aLen, bLen := 0, 0
		for _, op := range hunk {
			if op.kind != '+' {
				aLen++
			}
			if op.kind != '-' {
				bLen++
			}
		}
		fmt.Fprintf(w, "@@ -%d,%d +%d,%d @@\n", aStart, aLen, bStart, bLen)
		for _, op := range hunk {
			line := op.text
			noNewline := !strings.HasSuffix(line, "\n")
			fmt.Fprintf(w, "%c%s", op.kind, aisanitizer.Reveal(strings.TrimSuffix(line, "\n")))
			fmt.Fprintln(w)
			if noNewline {
				fmt.Fprintln(w, `\ No newline at end of file`)
			}
		}
		i = end
	}
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

type diffOp struct {
	kind   byte // ' ', '-', '+'
	text   string
	ai, bi int // line indexes in a and b at this op
}

// maxDiffEdits bounds the Myers search; beyond it the diff degrades to
// replacing the whole file, keeping memory at O(maxDiffEdits^2).
const maxDiffEdits = 4096

// diffLines computes a line diff with the Myers O(ND) algorithm.
func diffLines(a, b []string) []diffOp {
	n, m := len(a), len(b)
	maxD := min(n+m, maxDiffEdits)
	off := n + m
	v := make([]int, 2*off+2)
	// trace[d] holds v[-d..d] after round d.
	var trace [][]int
	dEnd := -1
outer:
	for d := 0; d <= maxD; d++ {
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				dEnd = d
				break outer
			}
		}
		trace = append(trace, append([]int(nil), v[off-d:off+d+1]...))
	}
	if dEnd < 0 {
		return replaceAll(a, b)
	}
	at := func(d, k int) int { return trace[d][k+d] }

	var ops []diffOp
	x, y := n, m
	for d := dEnd; d > 0; d-- {
		k := x - y
		prevK := k - 1
		if k == -d || (k != d && at(d-1, k-1) < at(d-1, k+1)) {
			prevK = k + 1
		}
		prevX := at(d-1, prevK)
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			x--
			y--
			ops = append(ops, diffOp{' ', a[x], x, y})
		}
		if x == prevX {
			y--
			ops = append(ops, diffOp{'+', b[y], x, y})
		} else {
			x--
			ops = append(ops, diffOp{'-', a[x], x, y})
		}
	}
	for x > 0 && y > 0 {
		x--
		y--
		ops = append(ops, diffOp{' ', a[x], x, y})
	}
	for i, j := 0, len(ops)-1; i < j; i, j = i+1, j-1 {
		ops[i], ops[j] = ops[j], ops[i]
	}
	return ops
}

func replaceAll(a, b []string) []diffOp {
	ops := make([]diffOp, 0, len(a)+len(b))
	for i, l := range a {
		ops = append(ops, diffOp{'-', l, i, 0})
	}
	for j, l := range b {
		ops = append(ops, diffOp{'+', l, len(a), j})
	}
	return ops
}
