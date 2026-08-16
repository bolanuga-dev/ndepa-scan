package main

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"gopkg.in/yaml.v3"
)

func evaluateManifest(t *testing.T, yamlContent string) []interface{} {
	t.Helper()

	var input map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlContent), &input); err != nil {
		t.Fatalf("Failed to parse YAML: %v", err)
	}

	ctx := context.Background()
	query, err := rego.New(
		rego.Query("data.ndepa.policies.deny"),
		rego.Module("ndpa_policies.rego", policyContent),
	).PrepareForEval(ctx)

	if err != nil {
		t.Fatalf("Failed to prepare OPA evaluation: %v", err)
	}

	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		t.Fatalf("Failed to evaluate policy: %v", err)
	}

	if len(results) > 0 && len(results[0].Expressions) > 0 {
		if rawViolations, ok := results[0].Expressions[0].Value.([]interface{}); ok {
			return rawViolations
		}
	}
	return nil
}

func TestNDPAPolicies_NonCompliantManifest(t *testing.T) {
	nonCompliantYAML := `
kubernetes_resources:
  - kind: Ingress
    metadata:
      name: insecure-ingress
      labels:
        ndpa-classification: pii
    spec:
      rules:
        - host: api.fintech.ng
`

	violations := evaluateManifest(t, nonCompliantYAML)
	if len(violations) == 0 {
		t.Errorf("Expected NDPA Section 39 violation for Ingress missing TLS, but got 0 violations")
	}
}

func TestNDPAPolicies_CompliantManifest(t *testing.T) {
	compliantYAML := `
kubernetes_resources:
  - kind: Ingress
    metadata:
      name: secure-ingress
      labels:
        ndpa-classification: pii
    spec:
      tls:
        - hosts:
            - api.fintech.ng
          secretName: api-tls-cert
      rules:
        - host: api.fintech.ng
`

	violations := evaluateManifest(t, compliantYAML)
	if len(violations) > 0 {
		t.Errorf("Expected 0 violations for compliant Ingress, but got %d: %v", len(violations), violations)
	}
}
