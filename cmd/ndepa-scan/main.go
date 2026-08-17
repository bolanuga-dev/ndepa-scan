package main

import (
	"context"
	"embed"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/bolanuga-dev/ndepa-scan/pkg/parser"
)

//go:embed ndpa_policies.rego
var embeddedPolicies embed.FS

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ndepa-scan <file-or-dir-or->")
		fmt.Println("Example: ndepa-scan ./terraform/plan.json")
		fmt.Println("Example: helm template . | ndepa-scan -")
		os.Exit(1)
	}

	targetPath := os.Args[1]

	// Determine input stream (stdin vs file)
	var reader io.Reader
	if targetPath == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(targetPath)
		if err != nil {
			log.Fatalf("Error opening target file: %v", err)
		}
		defer file.Close()
		reader = file
	}

	// Read and parse multi-document YAML or JSON stream
	documents, err := parser.ParseYAMLOrJSON(reader)
	if err != nil {
		log.Fatalf("Error parsing input: %v", err)
	}

	// Read embedded Rego policy content
	policyBytes, err := embeddedPolicies.ReadFile("ndpa_policies.rego")
	if err != nil {
		log.Fatalf("Failed to read embedded policy file: %v", err)
	}

	ctx := context.Background()

	// Compile Rego policy
	query, err := rego.New(
		rego.Query("data.ndepa.policies.deny"),
		rego.Module("ndpa_policies.rego", string(policyBytes)),
	).PrepareForEval(ctx)

	if err != nil {
		log.Fatalf("Failed to compile OPA policy: %v", err)
	}

	fmt.Println("==================================================================")
	fmt.Println("          NDPA 2023 COMPLIANCE SCANNER RESULTS                    ")
	fmt.Println("==================================================================")
	fmt.Printf("Target: %s\n", targetPath)
	fmt.Printf("Time:   %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Println("==================================================================")

	var violations []string

	// Evaluate every document parsed from the stream
	for _, doc := range documents {
		results, err := query.Eval(ctx, rego.EvalInput(doc))
		if err != nil {
			log.Fatalf("Failed to evaluate policy: %v", err)
		}

		if len(results) > 0 && len(results[0].Expressions) > 0 {
			if denials, ok := results[0].Expressions[0].Value.([]interface{}); ok {
				for _, d := range denials {
					violations = append(violations, fmt.Sprintf("%v", d))
				}
			}
		}
	}

	if len(violations) > 0 {
		fmt.Printf("\n❌ VIOLATIONS DETECTED (%d):\n", len(violations))
		for i, v := range violations {
			fmt.Printf("  %d. %s\n", i+1, v)
		}
		os.Exit(1)
	} else {
		fmt.Println("\n  PASS: No NDPA violations detected!")
		os.Exit(0)
	}
}
