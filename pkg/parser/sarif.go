package parser

import (
	"encoding/json"
)

type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string           `json:"id"`
	ShortDescription SARIFDescription `json:"shortDescription"`
	HelpURI          string           `json:"helpUri,omitempty"`
}

type SARIFDescription struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFDescription `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

func ConvertViolationsToSARIF(target string, violations []string) ([]byte, error) {
	ruleIDMap := map[string]string{
		"runAsNonRoot":             "NDPA-SEC39-NONROOT",
		"readOnlyRootFilesystem":   "NDPA-SEC39-READONLY-FS",
		"allowPrivilegeEscalation": "NDPA-SEC39-NO-PRIV-ESC",
		"S3 Encryption":           "NDPA-SEC24-S3-ENCRYPT",
	}

	rules := []SARIFRule{
		{
			ID:               "NDPA-SEC39-NONROOT",
			ShortDescription: SARIFDescription{Text: "NDPA Section 39: Container must run as non-root user"},
			HelpURI:          "https://ndpc.gov.ng/ndpa-compliance",
		},
		{
			ID:               "NDPA-SEC39-READONLY-FS",
			ShortDescription: SARIFDescription{Text: "NDPA Section 39: Container root filesystem must be read-only"},
			HelpURI:          "https://ndpc.gov.ng/ndpa-compliance",
		},
		{
			ID:               "NDPA-SEC39-NO-PRIV-ESC",
			ShortDescription: SARIFDescription{Text: "NDPA Section 39: Container privilege escalation must be disabled"},
			HelpURI:          "https://ndpc.gov.ng/ndpa-compliance",
		},
	}

	results := []SARIFResult{}
	uriTarget := target
	if uriTarget == "-" {
		uriTarget = "stdin.yaml"
	}

	for _, v := range violations {
		rID := "NDPA-GENERIC-VIOLATION"
		for key, mappedID := range ruleIDMap {
			if containsSubstring(v, key) {
				rID = mappedID
				break
			}
		}

		results = append(results, SARIFResult{
			RuleID:  rID,
			Level:   "error",
			Message: SARIFDescription{Text: v},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: uriTarget},
						Region:           SARIFRegion{StartLine: 1},
					},
				},
			},
		})
	}

	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "ndepa-scan",
						InformationURI: "https://github.com/bolanuga-dev/ndepa-scan",
						Version:        "1.2.0",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return json.MarshalIndent(report, "", "  ")
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
