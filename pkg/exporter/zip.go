package exporter

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

func CreateBundle(report *ComplianceReport, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	// Map ComplianceReport to AuditReportData
	var complianceMatrix []ComplianceRule
	for _, f := range report.Findings {
		complianceMatrix = append(complianceMatrix, ComplianceRule{
			Clause:   f.RuleID,
			Category: f.Severity,
			Finding:  f.Description,
			Verdict:  report.Status,
		})
	}

	var telemetryItems []TelemetryItem
	for _, e := range report.Egress {
		telemetryItems = append(telemetryItems, TelemetryItem{
			Description: fmt.Sprintf("[%s] %s", e.Timestamp, e.Protocol),
			Details:     e.Destination,
		})
	}

	auditData := AuditReportData{
		Organization:     report.Metadata.CompanyName,
		DPCOLicense:      report.Metadata.DPCOID,
		Scope:            report.Metadata.TargetScope,
		GeneratedAt:      report.Metadata.Timestamp.Format("2006-01-02 15:04:05"),
		ComplianceMatrix: complianceMatrix,
		TelemetryEvents:  telemetryItems,
		ManifestSHA256:   "VERIFIED-LOCAL-BUILD",
		EngineVersion:    "v1.0.0",
	}

	// Define intermediate PDF path
	reportPDFPath := filepath.Join(outputDir, fmt.Sprintf("audit_report_%s.pdf", report.Metadata.CompanyName))

	// Generate PDF (returns only error)
	err := GeneratePDF(auditData, reportPDFPath)
	if err != nil {
		return "", err
	}

	// Create ZIP archive path
	zipFileName := fmt.Sprintf("car_bundle_%s_%s.zip", report.Metadata.CompanyName, time.Now().Format("20060102_150405"))
	zipPath := filepath.Join(outputDir, zipFileName)

	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip file: %w", err)
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	defer archive.Close()

	// Add generated PDF to ZIP
	pdfFile, err := os.Open(reportPDFPath)
	if err != nil {
		return "", err
	}
	defer pdfFile.Close()

	writer, err := archive.Create(filepath.Base(reportPDFPath))
	if err != nil {
		return "", err
	}

	if _, err = io.Copy(writer, pdfFile); err != nil {
		return "", err
	}

	return zipPath, nil
}
