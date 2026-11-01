package aisanitizer

import "sort"

//go:generate go run ../internal/ucdgen -out tables_gen.go -emoji-testdata testdata/emoji-fully-qualified.txt

// runePair is a generated (rune, rune) table entry.
type runePair struct{ a, b rune }

// runeString is a generated rune → string table entry.
type runeString struct {
	r rune
	s string
}

func lookupString(table []runeString, r rune) (string, bool) {
	i := sort.Search(len(table), func(i int) bool { return table[i].r >= r })
	if i < len(table) && table[i].r == r {
		return table[i].s, true
	}
	return "", false
}

func isStandardizedVariant(base, vs rune) bool {
	t := stdVariants[:]
	i := sort.Search(len(t), func(i int) bool {
		return t[i].a > base || (t[i].a == base && t[i].b >= vs)
	})
	return i < len(t) && t[i].a == base && t[i].b == vs
}

func confusableTarget(r rune) (rune, bool) {
	t := confusableLatin[:]
	i := sort.Search(len(t), func(i int) bool { return t[i].a >= r })
	if i < len(t) && t[i].a == r {
		return t[i].b, true
	}
	return 0, false
}

func compatFold(r rune) (string, bool) {
	return lookupString(compatFoldTable[:], r)
}
