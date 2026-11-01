package aisanitizer

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files (testdata/golden/*.want.txt, *.report.json, README rules table)")

// goldenCases maps each testdata/golden/<name>.input.txt to the options it
// is sanitized with. <name>.want.txt holds the expected output and
// <name>.report.json the expected Detect report.
var goldenCases = map[string]func() *Options{
	"chatgpt_search":   Defaults,
	"other_assistants": Defaults,
	"emoji":            Defaults,
	"multilingual":     Defaults,
	"french":           func() *Options { return withOpts(func(o *Options) { o.KeepFrenchSpacing = true }) },
	"code_and_urls":    mustPreset(PresetPlain),
	"stego":            Defaults,
	"chat_markdown":    mustPreset(PresetParanoid),
}

// unchangedGolden lists cases whose input must survive byte-for-byte.
var unchangedGolden = map[string]bool{"emoji": true, "multilingual": true}

func mustPreset(name string) func() *Options {
	return func() *Options {
		o, err := Preset(name)
		if err != nil {
			panic(err)
		}
		return o
	}
}

func TestGolden(t *testing.T) {
	inputs, _ := filepath.Glob("testdata/golden/*.input.txt")
	if len(inputs) != len(goldenCases) {
		t.Fatalf("found %d golden inputs, %d cases", len(inputs), len(goldenCases))
	}
	for name, opts := range goldenCases {
		t.Run(name, func(t *testing.T) {
			base := filepath.Join("testdata", "golden", name)
			in, err := os.ReadFile(base + ".input.txt")
			if err != nil {
				t.Fatal(err)
			}
			o := opts()
			o.MaxPositions = 3
			got, _ := Sanitize(string(in), o)
			rep, err := Detect(string(in), o)
			if err != nil {
				t.Fatal(err)
			}
			repJSON, _ := json.MarshalIndent(rep, "", "  ")
			repJSON = append(repJSON, '\n')

			if unchangedGolden[name] && got != string(in) {
				t.Errorf("input changed:\n got  %+q\n want %+q", got, in)
			}
			if again, _ := Sanitize(got, o); again != got {
				t.Errorf("not idempotent:\n first  %+q\n second %+q", got, again)
			}
			if *update {
				writeFile(t, base+".want.txt", []byte(got))
				writeFile(t, base+".report.json", repJSON)
				return
			}
			want, err := os.ReadFile(base + ".want.txt")
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("output mismatch (run go test -update to accept):\n got  %+q\n want %+q", got, want)
			}
			wantRep, err := os.ReadFile(base + ".report.json")
			if err != nil {
				t.Fatal(err)
			}
			if string(repJSON) != string(wantRep) {
				t.Errorf("report mismatch (run go test -update to accept):\n%s", repJSON)
			}
		})
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
