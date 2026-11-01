package main

import (
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/iSerter/go-ai-text-sanitizer/aisanitizer"
)

// Minimal SARIF 2.1.0 structures, enough for GitHub code scanning.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	DefaultConfig    sarifConfig  `json:"defaultConfiguration"`
	Properties       sarifProps   `json:"properties"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifProps struct {
	Tags []string `json:"tags"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

func sarifLevel(category string) string {
	switch category {
	case aisanitizer.CategorySteganography, aisanitizer.CategoryHomoglyph:
		return "error"
	case aisanitizer.CategoryInvisible, aisanitizer.CategoryArtifact, aisanitizer.CategoryEncoding:
		return "warning"
	}
	return "note"
}

func writeSARIF(w io.Writer, results []*fileResult) error {
	run := sarifRun{Tool: sarifTool{Driver: sarifDriver{
		Name:           "ai-text-sanitizer",
		Version:        version,
		InformationURI: "https://github.com/iSerter/go-ai-text-sanitizer",
	}}, Results: []sarifResult{}}
	for _, r := range aisanitizer.Rules() {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:               string(r.ID),
			ShortDescription: sarifMessage{r.Description},
			DefaultConfig:    sarifConfig{sarifLevel(r.Category)},
			Properties:       sarifProps{Tags: []string{r.Category}},
		})
	}
	for _, fr := range results {
		uri := filepath.ToSlash(fr.Path)
		for _, f := range fr.Report.Findings {
			res := sarifResult{RuleID: string(f.Rule), Level: sarifLevel(f.Category), Message: sarifMessage{f.String()}}
			if len(f.Positions) == 0 {
				res.Locations = []sarifLocation{{sarifPhysical{ArtifactLocation: sarifArtifact{uri}}}}
			}
			for _, p := range f.Positions {
				res.Locations = append(res.Locations, sarifLocation{sarifPhysical{
					ArtifactLocation: sarifArtifact{uri},
					Region:           &sarifRegion{StartLine: p.Line, StartColumn: p.Column},
				}})
			}
			run.Results = append(run.Results, res)
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}
