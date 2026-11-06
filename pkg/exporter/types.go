package exporter

import "time"

type AuditReportData struct {
	Organization     string
	DPCOLicense      string
	Scope            string
	GeneratedAt      string
	ComplianceMatrix []ComplianceRule
	TelemetryEvents  []TelemetryItem
	ManifestSHA256   string
	EngineVersion    string
}

type ComplianceRule struct {
	Clause      string
	Category    string
	Finding     string
	Verdict     string
	RuleID      string
	Severity    string
	Description string
}

type ComplianceReport struct {
	Metadata       AuditMetadata
	Findings       []StaticFinding
	Egress         []EgressEvent
	Status         string
}

type StaticFinding struct {
	ID          string
	RuleID      string
	Description string
	Severity    string
}

type EgressEvent struct {
	Timestamp   string
	Destination string
	Protocol    string
	Status      string
}

type TelemetryItem struct {
	Description string
	Details     string
}

type AuditMetadata struct {
	CompanyName string
	Controller  string
	DPCOID      string
	TargetScope string
	Timestamp   time.Time
}
