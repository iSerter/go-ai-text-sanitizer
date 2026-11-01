package aisanitizer

import "sort"

// rewriter builds a modified copy of src from in-order replacements. Nothing
// is allocated until the first replacement, and unchanged input is returned
// as-is. It also records how output offsets map back to src offsets so that
// findings from later pipeline stages can be reported against the original
// input.
type rewriter struct {
	src   string
	out   []byte
	last  int // src[:last] has been consumed
	segs  []segment
	dirty bool
}

// segment marks that output starting at out came from src starting at in.
// For replacement text (repl) every output offset maps to in.
type segment struct {
	out, in int
	repl    bool
}

// replace substitutes src[i:j] with repl. Calls must be made with
// non-decreasing i, and i must not precede the end of the previous call.
func (w *rewriter) replace(i, j int, repl string) {
	if !w.dirty {
		w.dirty = true
		w.out = make([]byte, 0, len(w.src)+len(repl))
	}
	w.copyTo(i)
	if repl != "" {
		w.segs = append(w.segs, segment{len(w.out), i, true})
		w.out = append(w.out, repl...)
	}
	w.last = j
}

func (w *rewriter) copyTo(i int) {
	if i > w.last {
		w.segs = append(w.segs, segment{len(w.out), w.last, false})
		w.out = append(w.out, w.src[w.last:i]...)
		w.last = i
	}
}

// removeTidy removes src[i:j] and repairs the whitespace around the gap:
// "a [x] b" becomes "a b" and "a [x]." becomes "a.".
func (w *rewriter) removeTidy(i, j int) {
	w.replace(i, j, "")
	n := len(w.out)
	prevSpace := n > 0 && (w.out[n-1] == ' ' || w.out[n-1] == '\t')
	lineStart := n == 0 || w.out[n-1] == '\n'
	var next byte
	if j < len(w.src) {
		next = w.src[j]
	}
	switch {
	case (prevSpace || lineStart) && (next == ' ' || next == '\t'):
		w.last = j + 1
	case prevSpace && (next == 0 || next == '\n' || next == '\r' || isClosingPunct(next)):
		for n > 0 && (w.out[n-1] == ' ' || w.out[n-1] == '\t') {
			n--
		}
		w.out = w.out[:n]
		for len(w.segs) > 0 && w.segs[len(w.segs)-1].out >= n {
			w.segs = w.segs[:len(w.segs)-1]
		}
	}
}

func isClosingPunct(b byte) bool {
	switch b {
	case '.', ',', ';', ':', '!', '?', ')', ']', '}':
		return true
	}
	return false
}

func (w *rewriter) String() string {
	if !w.dirty {
		return w.src
	}
	w.copyTo(len(w.src))
	return string(w.out)
}

// offsetMap maps output offsets back to source offsets; nil means identity.
type offsetMap struct{ segs []segment }

func (w *rewriter) offsetMap() *offsetMap {
	if !w.dirty {
		return nil
	}
	return &offsetMap{segs: w.segs}
}

func (m *offsetMap) toSource(p int) int {
	if m == nil || len(m.segs) == 0 {
		return p
	}
	k := sort.Search(len(m.segs), func(i int) bool { return m.segs[i].out > p }) - 1
	if k < 0 {
		return m.segs[0].in
	}
	s := m.segs[k]
	if s.repl {
		return s.in
	}
	return s.in + (p - s.out)
}
