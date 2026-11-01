package aisanitizer

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// Go sources must spell invisible characters as escapes, never literally:
// literal ones are unreviewable and would be stripped by this very tool.
func TestNoLiteralInvisibleCharactersInSources(t *testing.T) {
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (strings.HasPrefix(d.Name(), ".") && d.Name() != "..") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		line := 1
		for i := 0; i < len(data); {
			r, size := utf8.DecodeRune(data[i:])
			switch {
			case r == '\n':
				line++
			case r == utf8.RuneError && size == 1:
				t.Errorf("%s:%d: invalid UTF-8", path, line)
			case (r < 0x20 && r != '\t' && r != '\r') || (r >= 0x80 && classify(r) != clsNone):
				t.Errorf("%s:%d: literal U+%04X; use an escape sequence", path, line, r)
			}
			i += size
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
