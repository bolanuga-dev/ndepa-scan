package main

import (
	"embed"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ndepa-scan/ndepa-scan/pkg/parser" 
	"github.com/open-policy-agent/opa/rego"
)

//go:embed ndpa_policies.rego
var embeddedPolicies embed.FS

type ScanResult struct {
	Target     string    `json:"target"`
	Time       string    `json:"timestamp"`
	Status     string    `json:"status"`
	Violations []string  `json:"violations"`
}

func main() {
	policyDir := flag.String("policy-dir", "", "Directory containing custom Rego policies")
	outputFormat := flag.String("output", "text", "Output format: text, json")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		log.Fatalf("Usage: ndepa-scan [--policy-dir DIR] [--output text|json] <file-or-stdin>")
	}
	targetPath := args[0]

	// Handle input reading
	var reader io.Reader
	if targetPath == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(targetPath)
		if err != nil {
			log.Fatalf("Failed to open file: %v", err)
		}
		defer file.Close()
		reader = file
	}

	// Parse documents
	documents, err := parser.ParseYAMLOrJSON(reader)
	if err != nil {
		log.Fatalf("Error parsing input: %v", err)
	}

	// Prepare Rego evaluation options
	var regoOptions []func(*rego.Rego)
	regoOptions = append(regoOptions, rego.Query("data.ndepa.policies.deny"))

	// 1. Load Embedded Policies
	policyBytes, err := embeddedPolicies.ReadFile("ndpa_policies.rego")
	if err != nil {
		log.Fatalf("Failed to read embedded policy file: %v", err)
	}
	regoOptions = append(regoOptions, rego.Module("ndpa_policies.rego", string(policyBytes)))

	// 2. Load Custom Policy Directory (if flag is passed)
	if *policyDir != "" {
		files, err := os.ReadDir(*policyDir)
		if err != nil {
			log.Fatalf("Failed to read custom policy dir: %v", err)
		}
		for _, f := range files {
			if !f.IsDir() && filepath.Ext(f.Name()) == ".rego" {
				content, err := os.ReadFile(filepath.Join(*policyDir, f.Name()))
				if err != nil {
					log.Fatalf("Failed to read policy %s: %v", f.Name(), err)
				}
				regoOptions = append(regoOptions, rego.Module(f.Name(), string(content)))
			}
		}
	}

	ctx := context.Background()
	query, err := rego.New(regoOptions...).PrepareForEval(ctx)
	if err != nil {
		log.Fatalf("Failed to compile OPA policy: %v", err)
	}

	var allViolations []string
	for _, doc := range documents {
		results, err := query.Eval(ctx, rego.EvalInput(doc))
		if err != nil {
			log.Fatalf("Policy evaluation failed: %v", err)
		}
		if len(results) > 0 {
			for _, expression := range results[0].Expressions {
				if items, ok := expression.Value.([]interface{}); ok {
					for _, item := range items {
						allViolations = append(allViolations, fmt.Sprintf("%v", item))
					}
				}
			}
		}
	}


// Output Formatting
	timestamp := time.Now().UTC().Format(time.RFC3339)
	status := "PASS"
	if len(allViolations) > 0 {
		status = "FAIL"
	}

	switch *outputFormat {
	case "json":
		res := ScanResult{
			Target:     targetPath,
			Time:       timestamp,
			Status:     status,
			Violations: allViolations,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(res)

	case "sarif":
        	sarifBytes, err := parser.ConvertViolationsToSARIF(targetPath, allViolations)
		if err != nil {
			log.Fatalf("Error generating SARIF output: %v", err)
		}
		fmt.Println(string(sarifBytes))

	default:
		fmt.Println("==================================================")
		fmt.Println("       NDPA 2023 COMPLIANCE SCANNER RESULTS       ")
		fmt.Println("==================================================")
		fmt.Printf("Target: %s\n", targetPath)
		fmt.Printf("Time:   %s\n", timestamp)
		fmt.Println("==================================================")
		fmt.Println()

                if len(allViolations) > 0 {
		   fmt.Printf("❌ VIOLATIONS DETECTED (%d):\n", len(allViolations))
		   for i, v := range allViolations {
		      fmt.Printf("  %d. %s\n", i+1, v)
		   }
		} else {
		   fmt.Println("PASS: No NDPA violations detected!")
		}
	     } // Closes switch *outputFormat
          }     // Closes func main()
