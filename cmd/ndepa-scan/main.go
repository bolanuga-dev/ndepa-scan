package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"gopkg.in/yaml.v3"
)

//go:embed ndpa_policies.rego
var policyContent string

type Finding struct {
	ID          int    `json:"id"`
	Rule        string `json:"rule"`
	Description string `json:"description"`
}

type ScanReport struct {
	Timestamp   string    `json:"timestamp"`
	TargetFile  string    `json:"target_file"`
	TotalErrors int       `json:"total_errors"`
	Status      string    `json:"status"`
	Findings    []Finding `json:"findings"`
}

func main() {
	formatFlag := flag.String("format", "text", "Output format: 'text' or 'json'")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("Usage: ndepa-scan [--format=text|json] <path-to-manifest>")
		os.Exit(1)
	}

	manifestPath := args[0]
	fileBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		log.Fatalf("Error reading file %s: %v", manifestPath, err)
	}

	// Unmarshal input dynamically based on file extension
	var input map[string]interface{}
	ext := strings.ToLower(filepath.Ext(manifestPath))

	if ext == ".yaml" || ext == ".yml" {
		if err := yaml.Unmarshal(fileBytes, &input); err != nil {
			log.Fatalf("Error parsing YAML manifest: %v", err)
		}
	} else {
		if err := json.Unmarshal(fileBytes, &input); err != nil {
			log.Fatalf("Error parsing JSON manifest: %v", err)
		}
	}

	ctx := context.Background()

	query, err := rego.New(
		rego.Query("data.ndepa.policies.deny"),
		rego.Module("ndpa_policies.rego", policyContent),
	).PrepareForEval(ctx)

	if err != nil {
		log.Fatalf("Failed to initialize OPA engine: %v", err)
	}

	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatalf("Error evaluating policy: %v", err)
	}

	report := ScanReport{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		TargetFile: manifestPath,
		Status:     "PASS",
		Findings:   []Finding{},
	}

	if len(results) > 0 && len(results[0].Expressions) > 0 {
		rawViolations, ok := results[0].Expressions[0].Value.([]interface{})
		if ok && len(rawViolations) > 0 {
			report.Status = "FAIL"
			report.TotalErrors = len(rawViolations)

			for i, v := range rawViolations {
				report.Findings = append(report.Findings, Finding{
					ID:          i + 1,
					Rule:        "NDPA Policy Violation",
					Description: fmt.Sprintf("%v", v),
				})
			}
		}
	}

	if *formatFlag == "json" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(report); err != nil {
			log.Fatalf("Error generating JSON report: %v", err)
		}
	} else {
		renderTextReport(report)
	}

	if report.Status == "FAIL" {
		os.Exit(1)
	}
}

func renderTextReport(report ScanReport) {
	fmt.Println("=======================================================")
	fmt.Println("       NDPA 2023 COMPLIANCE SCANNER RESULTS           ")
	fmt.Println("=======================================================")
	fmt.Printf(" Target: %s\n", report.TargetFile)
	fmt.Printf(" Time:   %s\n", report.Timestamp)
	fmt.Println("=======================================================")

	if report.Status == "FAIL" {
		fmt.Printf("\n❌ Found %d NDPA Violation(s):\n\n", report.TotalErrors)
		for _, f := range report.Findings {
			fmt.Printf("[%d] %s\n", f.ID, f.Description)
		}
		fmt.Println("\nResult: FAIL ❌ (Fix violations prior to DPCO Audit Returns)")
	} else {
		fmt.Println("\n✅ PASS: No NDPA violations detected!")
	}
}
