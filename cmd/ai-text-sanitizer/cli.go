package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/iSerter/go-ai-text-sanitizer/aisanitizer"
)

const (
	exitOK       = 0
	exitError    = 1
	exitFindings = 2
)

const usageHeader = `ai-text-sanitizer %s - remove invisible Unicode watermarks, hidden payloads
and LLM artifacts from text (Unicode %s tables).

Usage:
  ai-text-sanitizer [flags] [file|dir ...]
  ai-text-sanitizer serve [flags]   run the HTTP API (see serve --help)

With no inputs (or "-"), reads stdin. Flags may appear before or after inputs.
To process a file named "serve", pass it as ./serve.

Modes:
  (default)        write sanitized text to stdout, or to -o FILE
  -i, --in-place   rewrite files in place (atomic; keeps FILE.bak unless --no-backup)
  -d, --detect-only  print findings without modifying anything; exit 2 if any
  --check          list inputs that would change; exit 2 if any
  --diff           print a unified diff of the changes

Exit codes: 0 success, 1 error, 2 findings/changes (with --detect-only,
--check or --strict).

Flags:
`

// fileResult is one processed input.
type fileResult struct {
	Path   string              `json:"path"`
	Report *aisanitizer.Report `json:"report"`

	input, output string
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "serve" {
		return runServe(args[1:], stderr)
	}
	var c config
	fs := newFlagSet(&c)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, usageHeader, version, aisanitizer.UnicodeVersion)
		fs.PrintDefaults()
	}
	flags, inputs := splitArgs(fs, args)
	if err := fs.Parse(flags); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError
	}
	if c.version {
		fmt.Fprintln(stdout, version)
		return exitOK
	}
	if c.listRules {
		listRules(stdout)
		return exitOK
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "ai-text-sanitizer: "+format+"\n", a...)
		return exitError
	}
	opts, err := c.options()
	if err != nil {
		return fail("%v", err)
	}
	switch c.format {
	case "text", "json", "sarif":
	default:
		return fail("invalid --format %q (want text, json or sarif)", c.format)
	}
	if c.format == "sarif" && opts.MaxPositions == 0 {
		opts.MaxPositions = 100
	}
	modes := 0
	for _, m := range []bool{c.detectOnly, c.check, c.diff, c.inPlace} {
		if m {
			modes++
		}
	}
	if modes > 1 {
		return fail("--detect-only, --check, --diff and --in-place are mutually exclusive")
	}
	if c.out != "" && (modes > 0 && !c.diff) {
		return fail("-o/--out cannot be combined with --detect-only, --check or --in-place")
	}

	paths, walked, err := expandInputs(inputs, c.includes, c.excludes)
	if err != nil {
		return fail("%v", err)
	}
	if len(paths) == 0 && len(inputs) > 0 {
		return fail("no input files matched")
	}
	if len(paths) == 0 {
		paths = []string{"-"}
	}
	if c.inPlace {
		for _, p := range paths {
			if p == "-" {
				return fail("--in-place needs file arguments")
			}
		}
	}
	if len(paths) > 1 && modes == 0 {
		return fail("multiple inputs need --in-place, --check, --detect-only or --diff")
	}

	status := exitOK
	var results []*fileResult
	for _, p := range paths {
		res, err := c.process(p, opts, stdin)
		var utf8Err *invalidUTF8Error
		if errors.As(err, &utf8Err) && walked[p] {
			// Found by a directory walk: likely a legacy-encoded or binary
			// file rather than text this tool should rewrite.
			fmt.Fprintf(stderr, "ai-text-sanitizer: skipping %v\n", err)
			continue
		}
		if err != nil {
			fmt.Fprintf(stderr, "ai-text-sanitizer: %v\n", err)
			status = exitError
			continue
		}
		results = append(results, res)
		if c.pretty {
			fmt.Fprintf(stderr, "%s: %s", displayName(p), res.Report.String())
		}
	}

	if err := c.emit(results, opts, stdout); err != nil {
		return fail("%v", err)
	}
	if c.report != "" {
		if err := writeReport(c.report, results); err != nil {
			return fail("writing report: %v", err)
		}
	}
	if status != exitOK {
		return status
	}
	for _, r := range results {
		switch {
		case c.detectOnly && r.Report.HasFindings(),
			c.check && r.Report.Modified,
			c.strict && (r.Report.Modified || r.Report.HasFindings()):
			return exitFindings
		}
	}
	return exitOK
}

func (c *config) process(path string, opts *aisanitizer.Options, stdin io.Reader) (*fileResult, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	input := string(data)
	if strings.EqualFold(c.invalidUTF8, "error") {
		if err := aisanitizer.CheckUTF8(input); err != nil {
			return nil, &invalidUTF8Error{displayName(path), err}
		}
	}
	res := &fileResult{Path: displayName(path), input: input}
	if c.detectOnly {
		res.Report, err = aisanitizer.Detect(input, opts)
		res.output = input
		return res, err
	}
	res.output, res.Report = aisanitizer.Sanitize(input, opts)
	if c.inPlace && res.Report.Modified {
		if err := writeInPlace(path, []byte(res.output), !c.noBackup); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// emit writes the mode-specific output to stdout (or -o).
func (c *config) emit(results []*fileResult, opts *aisanitizer.Options, stdout io.Writer) error {
	switch {
	case c.detectOnly:
		return writeFindings(stdout, c.format, results)
	case c.check:
		if c.format != "text" {
			return writeFindings(stdout, c.format, results)
		}
		for _, r := range results {
			if r.Report.Modified {
				fmt.Fprintln(stdout, r.Path)
			}
		}
		return nil
	case c.diff:
		var buf bytes.Buffer
		for _, r := range results {
			if r.Report.Modified {
				writeUnifiedDiff(&buf, r.Path, r.input, r.output)
			}
		}
		return writeOutput(c.out, stdout, buf.Bytes())
	case c.inPlace:
		return nil
	}
	if len(results) == 0 {
		return nil
	}
	return writeOutput(c.out, stdout, []byte(results[0].output))
}

func writeOutput(path string, stdout io.Writer, data []byte) error {
	if path == "" {
		_, err := stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeFindings(w io.Writer, format string, results []*fileResult) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	case "sarif":
		return writeSARIF(w, results)
	}
	for _, r := range results {
		if !r.Report.HasFindings() && !r.Report.Modified {
			continue
		}
		fmt.Fprintf(w, "%s: %s", r.Path, r.Report.String())
	}
	return nil
}

func writeReport(path string, results []*fileResult) error {
	var v any
	if len(results) == 1 {
		v = results[0].Report
	} else {
		total := &aisanitizer.Report{Risk: aisanitizer.RiskNone}
		for _, r := range results {
			total.Merge(r.Report)
		}
		v = struct {
			Files   []*fileResult       `json:"files"`
			Summary *aisanitizer.Report `json:"summary"`
		}{results, total}
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func displayName(path string) string {
	if path == "-" {
		return "<stdin>"
	}
	return path
}

func listRules(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tCATEGORY\tACTION\tDEFAULT\tOPTION")
	for _, r := range aisanitizer.Rules() {
		def := "off"
		if r.Default {
			def = "on"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Category, r.Action, def, r.Option)
	}
	tw.Flush()
}

// invalidUTF8Error reports an input rejected by --invalid-utf8=error.
type invalidUTF8Error struct {
	path string
	err  error
}

func (e *invalidUTF8Error) Error() string {
	return fmt.Sprintf("%s: %v (use --invalid-utf8=replace or drop)", e.path, e.err)
}

func (e *invalidUTF8Error) Unwrap() error { return e.err }

// expandInputs resolves file and directory arguments. Directories are walked
// recursively, skipping hidden entries, binary files and the FILE.bak
// backups written by --in-place; walked reports the paths found that way.
func expandInputs(inputs, includes, excludes []string) (out []string, walked map[string]bool, err error) {
	walked = map[string]bool{}
	for _, in := range inputs {
		if in == "-" {
			out = append(out, in)
			continue
		}
		info, err := os.Stat(in)
		if err != nil {
			return nil, nil, err
		}
		if !info.IsDir() {
			out = append(out, in)
			continue
		}
		var found []string
		err = filepath.WalkDir(in, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if p != in && (strings.HasPrefix(name, ".") || matchAny(excludes, p, name)) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			if strings.HasSuffix(name, ".bak") || (len(includes) > 0 && !matchAny(includes, p, name)) {
				return nil
			}
			if isBinary(p) {
				return nil
			}
			found = append(found, p)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		sort.Strings(found)
		for _, p := range found {
			walked[p] = true
		}
		out = append(out, found...)
	}
	return out, walked, nil
}

func matchAny(patterns []string, path, name string) bool {
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, name); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, filepath.ToSlash(path)); ok {
			return true
		}
	}
	return false
}

// isBinary reports whether the file's first 8 KiB contain a NUL byte.
func isBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := io.ReadFull(f, buf)
	return bytes.IndexByte(buf[:n], 0) >= 0
}

// writeInPlace atomically replaces path with data, preserving its mode, and
// optionally keeps the original as path.bak with the same mode.
func writeInPlace(path string, data []byte, backup bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if backup {
		orig, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := atomicWrite(path+".bak", orig, mode); err != nil {
			return fmt.Errorf("creating backup: %w", err)
		}
	}
	return atomicWrite(path, data, mode)
}

func atomicWrite(path string, data []byte, mode fs.FileMode) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
