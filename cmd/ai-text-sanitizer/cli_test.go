package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type result struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return result{code, out.String(), errb.String()}
}

func writeTemp(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStdinToStdout(t *testing.T) {
	r := runCLI(t, "hi\u200Bthere (oaicite:0){index=0}\n")
	if r.code != 0 || r.stdout != "hithere\n" {
		t.Errorf("got %+v", r)
	}
}

func TestFlagsAfterFileArgument(t *testing.T) {
	dir := t.TempDir()
	in := writeTemp(t, dir, "in.txt", "a\u200Bb\n", 0o644)
	out := filepath.Join(dir, "clean.txt")
	r := runCLI(t, "", in, "-o", out, "--report", filepath.Join(dir, "r.json"))
	if r.code != 0 || r.stdout != "" {
		t.Fatalf("got %+v", r)
	}
	if data, _ := os.ReadFile(out); string(data) != "ab\n" {
		t.Errorf("output file = %q", data)
	}
	var rep map[string]any
	data, _ := os.ReadFile(filepath.Join(dir, "r.json"))
	if err := json.Unmarshal(data, &rep); err != nil || rep["modified"] != true {
		t.Errorf("report = %s (%v)", data, err)
	}
}

func TestDetectOnly(t *testing.T) {
	r := runCLI(t, "a\u200Bb", "-d")
	if r.code != 2 || !strings.Contains(r.stdout, "U+200B ZERO WIDTH SPACE") || strings.Contains(r.stdout, "a\u200Bb") {
		t.Errorf("got %+v", r)
	}
	r = runCLI(t, "clean", "--detect-only")
	if r.code != 0 || r.stdout != "" {
		t.Errorf("clean input: %+v", r)
	}
	r = runCLI(t, "x\U000E0041\U000E0042", "-d", "--format", "json")
	var files []struct {
		Path   string
		Report struct {
			Risk     string
			Findings []struct{ Rule, Payload string }
		}
	}
	if err := json.Unmarshal([]byte(r.stdout), &files); err != nil || len(files) != 1 || files[0].Report.Risk != "high" {
		t.Fatalf("json = %s (%v)", r.stdout, err)
	}
}

func TestSARIF(t *testing.T) {
	dir := t.TempDir()
	p := writeTemp(t, dir, "doc.md", "line one\nsecond \u200B line\n", 0o644)
	r := runCLI(t, "", "-d", "--format", "sarif", p)
	if r.code != 2 {
		t.Fatalf("got %+v", r)
	}
	var log struct {
		Version string
		Runs    []struct {
			Results []struct {
				RuleID    string
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }
						Region           struct{ StartLine, StartColumn int }
					}
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(r.stdout), &log); err != nil {
		t.Fatal(err)
	}
	res := log.Runs[0].Results
	if log.Version != "2.1.0" || len(res) != 1 || res[0].RuleID != "zero_width" {
		t.Fatalf("sarif = %s", r.stdout)
	}
	loc := res[0].Locations[0].PhysicalLocation
	if loc.Region.StartLine != 2 || loc.Region.StartColumn != 8 || !strings.HasSuffix(loc.ArtifactLocation.URI, "doc.md") {
		t.Errorf("location = %+v", loc)
	}
}

func TestStrictExitCode(t *testing.T) {
	if r := runCLI(t, "a\u200Bb", "--strict"); r.code != 2 || r.stdout != "ab" {
		t.Errorf("got %+v", r)
	}
	if r := runCLI(t, "ab", "-s"); r.code != 0 {
		t.Errorf("got %+v", r)
	}
}

func TestInPlacePreservesModeAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	p := writeTemp(t, dir, "secret.txt", "top\u200Bsecret", 0o600)
	r := runCLI(t, "", p, "-i")
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	if data, _ := os.ReadFile(p); string(data) != "topsecret" {
		t.Errorf("file = %q", data)
	}
	if data, _ := os.ReadFile(p + ".bak"); string(data) != "top\u200Bsecret" {
		t.Errorf("backup = %q", data)
	}
	if runtime.GOOS != "windows" {
		for _, f := range []string{p, p + ".bak"} {
			if info, _ := os.Stat(f); info.Mode().Perm() != 0o600 {
				t.Errorf("%s mode = %v, want 0600", f, info.Mode().Perm())
			}
		}
	}
	// Unchanged files are not rewritten and get no backup.
	q := writeTemp(t, dir, "clean.txt", "clean", 0o644)
	runCLI(t, "", "-i", "--no-backup", q)
	if _, err := os.Stat(q + ".bak"); !os.IsNotExist(err) {
		t.Error("backup created for unchanged file")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestCheckAndDirectories(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "a.md", "dirty\u200B", 0o644)
	writeTemp(t, dir, "b.md", "clean", 0o644)
	writeTemp(t, dir, "sub/c.txt", "also\u00A0dirty", 0o644)
	writeTemp(t, dir, "sub/d.go", "x\u200B", 0o644)
	writeTemp(t, dir, ".git/e.md", "hidden\u200B", 0o644)
	writeTemp(t, dir, "bin.dat", "bin\x00ary\u200B", 0o644)

	r := runCLI(t, "", "--check", dir, "--exclude", "*.go")
	if r.code != 2 {
		t.Fatalf("got %+v", r)
	}
	got := strings.Split(strings.TrimSpace(r.stdout), "\n")
	want := []string{filepath.Join(dir, "a.md"), filepath.Join(dir, "sub", "c.txt")}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("check listed %v, want %v", got, want)
	}

	r = runCLI(t, "", "--check", dir, "--include", "*.md")
	if strings.TrimSpace(r.stdout) != filepath.Join(dir, "a.md") {
		t.Errorf("include: %q", r.stdout)
	}
	if r := runCLI(t, "", dir); r.code != 1 || !strings.Contains(r.stderr, "multiple inputs") {
		t.Errorf("multiple inputs without mode: %+v", r)
	}
}

func TestDiff(t *testing.T) {
	in := "one\ntwo\u200B\nthree\nfour\nfive\nsix\nseven\neight\nnine (oaicite:0){index=0}\nten\n"
	r := runCLI(t, in, "--diff")
	if r.code != 0 || !strings.Contains(r.stdout, "-two\u27E8U+200B\u27E9\n+two\n") || !strings.Contains(r.stdout, "-nine (oaicite:0){index=0}\n+nine\n") {
		t.Errorf("diff = %q", r.stdout)
	}
	// Changes 7 lines apart are separate hunks; closer ones merge.
	if !strings.HasPrefix(r.stdout, "--- a/<stdin>\n+++ b/<stdin>\n@@ -1,10 +1,10 @@\n one\n") {
		t.Errorf("unexpected hunks: %q", r.stdout)
	}
	far := "a\u200B\n2\n3\n4\n5\n6\n7\n8\nb\u200B\n"
	if r := runCLI(t, far, "--diff"); !strings.Contains(r.stdout, "@@ -1,4 +1,4 @@") || !strings.Contains(r.stdout, "@@ -6,4 +6,4 @@") {
		t.Errorf("separate hunks: %q", r.stdout)
	}
	if r := runCLI(t, "clean\n", "--diff"); r.stdout != "" {
		t.Errorf("diff of clean input: %q", r.stdout)
	}
}

func TestInvalidUTF8Policies(t *testing.T) {
	r := runCLI(t, "a\xffb")
	if r.code != 1 || !strings.Contains(r.stderr, "offset 1") {
		t.Errorf("error policy: %+v", r)
	}
	if r := runCLI(t, "a\xffb", "--invalid-utf8=replace"); r.code != 0 || r.stdout != "a\uFFFDb" {
		t.Errorf("replace: %+v", r)
	}
	if r := runCLI(t, "a\xffb", "--invalid-utf8", "drop"); r.stdout != "ab" {
		t.Errorf("drop: %+v", r)
	}
}

func TestOptionFlags(t *testing.T) {
	tests := []struct {
		args      []string
		in, want  string
		wantError bool
	}{
		{[]string{"--normalize-smart-quotes"}, "\u201Cq\u201D", "\"q\"", false},
		{[]string{"--preset", "plain"}, "## T\n\n\u201Cq\u201D \u2014 x\u2026 ", "T\n\n\"q\" - x...", false},
		{[]string{"--preset=plain", "--normalize-smart-quotes=false"}, "\u201Cq\u201D", "\u201Cq\u201D", false},
		{[]string{"--dash-style", "comma"}, "a \u2014 b \u2014 c", "a, b, c", false},
		{[]string{"--no-remove-zero-width"}, "a\u200Bb", "a\u200Bb", false},
		{[]string{"--no-rule", "zero_width,exotic_space"}, "a\u200Bb\u00A0c", "a\u200Bb\u00A0c", false},
		{[]string{"--rule", "artifact.numeric_citation"}, "x [1].", "x.", false},
		{[]string{"--nfkc"}, "\uFB01", "fi", false},
		{[]string{"--bidi", "keep"}, "a\u202Eb", "a\u202Eb", false},
		{[]string{"--collapse-whitespace", "--max-blank-lines", "2"}, "a\n\n\n\n\nb", "a\n\n\nb", false},
		{[]string{"--rewrite", "none"}, "a", "a", false},
		{[]string{"--rewrite", "light"}, "a", "", true},
		{[]string{"--rule", "bogus"}, "a", "", true},
		{[]string{"--preset", "bogus"}, "a", "", true},
		{[]string{"--dash-style", "bogus"}, "a", "", true},
		{[]string{"--format", "xml", "-d"}, "a", "", true},
		{[]string{"--max-blank-lines", "0"}, "a", "", true},
		{[]string{"-d", "-i"}, "a", "", true},
	}
	for _, tt := range tests {
		r := runCLI(t, tt.in, tt.args...)
		if tt.wantError {
			if r.code != 1 || r.stderr == "" {
				t.Errorf("%v: expected error, got %+v", tt.args, r)
			}
			continue
		}
		if r.code != 0 || r.stdout != tt.want {
			t.Errorf("%v: got %+v, want %q", tt.args, r, tt.want)
		}
	}
}

func TestListRulesAndVersion(t *testing.T) {
	r := runCLI(t, "", "--list-rules")
	if r.code != 0 || !strings.Contains(r.stdout, "zero_width") || !strings.Contains(r.stdout, "artifact.turn_citation") {
		t.Errorf("list-rules: %+v", r)
	}
	if r := runCLI(t, "", "-v"); r.stdout != "dev\n" {
		t.Errorf("version: %+v", r)
	}
	if r := runCLI(t, "", "-h"); r.code != 0 || !strings.Contains(r.stderr, "Usage:") {
		t.Errorf("help: %+v", r)
	}
}

func TestPretty(t *testing.T) {
	r := runCLI(t, "a\u200Bb", "--pretty")
	if r.stdout != "ab" || !strings.Contains(r.stderr, "<stdin>: Modified: true") {
		t.Errorf("got %+v", r)
	}
}

func TestMultiFileReport(t *testing.T) {
	dir := t.TempDir()
	a := writeTemp(t, dir, "a.txt", "x\u200B", 0o644)
	b := writeTemp(t, dir, "b.txt", "y\u200B\u200B", 0o644)
	rep := filepath.Join(dir, "r.json")
	runCLI(t, "", "-i", "--no-backup", a, b, "-r", rep)
	var v struct {
		Files   []struct{ Path string }
		Summary struct {
			Changes struct {
				RemovedZeroWidth int `json:"removed_zero_width"`
			}
		}
	}
	data, _ := os.ReadFile(rep)
	if err := json.Unmarshal(data, &v); err != nil || len(v.Files) != 2 || v.Summary.Changes.RemovedZeroWidth != 3 {
		t.Errorf("report = %s (%v)", data, err)
	}
}

func TestDiffLines(t *testing.T) {
	a := []string{"a\n", "b\n", "c\n"}
	b := []string{"a\n", "x\n", "c\n", "d\n"}
	var kinds []byte
	for _, op := range diffLines(a, b) {
		kinds = append(kinds, op.kind)
	}
	if string(kinds) != " -+ +" {
		t.Errorf("ops = %q", kinds)
	}
	// Large, scattered edits stay correct.
	var big, big2 []string
	for i := 0; i < 5000; i++ {
		l := strings.Repeat("x", i%7) + "\n"
		big = append(big, l)
		if i%3 == 0 {
			l = "changed\n"
		}
		big2 = append(big2, l)
	}
	var gotA, gotB []string
	for _, op := range diffLines(big, big2) {
		if op.kind != '+' {
			gotA = append(gotA, op.text)
		}
		if op.kind != '-' {
			gotB = append(gotB, op.text)
		}
	}
	if strings.Join(gotA, "") != strings.Join(big, "") || strings.Join(gotB, "") != strings.Join(big2, "") {
		t.Error("diff does not reconstruct its inputs")
	}
	if ops := diffLines(nil, nil); len(ops) != 0 {
		t.Errorf("empty diff = %v", ops)
	}
}

func TestDirectoryWalkSkipsBackups(t *testing.T) {
	dir := t.TempDir()
	a := writeTemp(t, dir, "a.md", "one\u200B", 0o644)
	if r := runCLI(t, "", "-i", dir); r.code != 0 {
		t.Fatalf("first run: %+v", r)
	}
	writeTemp(t, dir, "a.md", "two\u200B", 0o644)
	if r := runCLI(t, "", "-i", dir); r.code != 0 {
		t.Fatalf("second run: %+v", r)
	}
	if data, _ := os.ReadFile(a + ".bak"); string(data) != "two\u200B" {
		t.Errorf("backup = %q", data)
	}
	if _, err := os.Stat(a + ".bak.bak"); !os.IsNotExist(err) {
		t.Errorf("backup of backup created (%v)", err)
	}
	// Named explicitly, a .bak file is still processed.
	if r := runCLI(t, "", "--check", a+".bak"); r.code != 2 {
		t.Errorf("explicit .bak: %+v", r)
	}
}

func TestDirectoryWalkSkipsInvalidUTF8(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "latin1.txt", "caf\xe9", 0o644)
	writeTemp(t, dir, "b.md", "x\u200B", 0o644)
	r := runCLI(t, "", "--detect-only", dir)
	if r.code != 2 || !strings.Contains(r.stderr, "skipping") || !strings.Contains(r.stderr, "latin1.txt") {
		t.Errorf("walk: %+v", r)
	}
	r = runCLI(t, "", "--detect-only", filepath.Join(dir, "latin1.txt"))
	if r.code != 1 {
		t.Errorf("explicit file: %+v", r)
	}
}
