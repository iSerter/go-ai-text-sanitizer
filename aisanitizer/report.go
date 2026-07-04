package aisanitizer

import "fmt"

type ChangeStats struct {
	RemovedZeroWidth            int
	RemovedBidi                 int
	RemovedInvisibleMath        int
	RemovedVariationSelectors   int
	RemovedTagChars             int
	RemovedFormatChars          int
	RemovedBrailleBlank         int
	RemovedControl              int
	RemovedCitations            int
	RemovedModelArtifacts       int
	NormalizedSpaces            int
	NormalizedLineSeparators    int
	NormalizedSmartQuotes       int
	NormalizedDashes            int
	NormalizedEllipsis          int
	CollapsedSpaces             int
	RewrittenSegments           int
	Total                       int
}

type Finding struct {
	Category  string
	Name      string
	Notation  string
	CodePoint rune
	Index     int
	Count     int
}

func (f *Finding) String() string {
	return fmt.Sprintf("%s %s [%s] x%d", f.Notation, f.Name, f.Category, f.Count)
}

type Report struct {
	Modified bool
	Changes  ChangeStats
	Findings []Finding
}

func (r *Report) WasModified() bool {
	return r.Modified
}

func (r *Report) HasWatermarks() bool {
	return len(r.Findings) > 0
}

func (r *Report) Summary() string {
	if !r.Modified && !r.HasWatermarks() {
		return "No changes made."
	}
	return fmt.Sprintf("Modified: %v, Changes: %d, Findings: %d",
		r.Modified, r.Changes.Total, len(r.Findings))
}
