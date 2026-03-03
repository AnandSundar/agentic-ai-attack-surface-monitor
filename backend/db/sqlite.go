package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/glebarez/sqlite"
)

var DB *sql.DB

type Scan struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Status    string    `json:"status"`
	Summary   string    `json:"summary,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Finding struct {
	ID           string `json:"id"`
	ScanID       string `json:"scan_id"`
	Subdomain    string `json:"subdomain"`
	Risk         string `json:"risk"`
	OpenPorts    string `json:"open_ports,omitempty"`
	Tech         string `json:"tech,omitempty"`
	TechVersion  string `json:"tech_version,omitempty"`
	Outdated     bool   `json:"outdated"`
	Headers      string `json:"headers,omitempty"`
}

func InitDB(dataDir string) error {
	if dataDir == "" {
		dataDir = "."
	}

	dbPath := filepath.Join(dataDir, "attack_surface.db")

	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_foreign_keys=on")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	DB = db

	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	return nil
}

func createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id          TEXT PRIMARY KEY,
		domain      TEXT NOT NULL,
		status      TEXT NOT NULL DEFAULT 'running',
		summary     TEXT,
		created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS findings (
		id          TEXT PRIMARY KEY,
		scan_id     TEXT NOT NULL,
		subdomain   TEXT NOT NULL,
		risk        TEXT NOT NULL,
		open_ports  TEXT,
		tech        TEXT,
		tech_version TEXT,
		outdated    INTEGER DEFAULT 0,
		headers     TEXT,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
	CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
	`

	_, err := DB.Exec(schema)
	return err
}

func CreateScan(ctx context.Context, id, domain string) (*Scan, error) {
	scan := &Scan{
		ID:        id,
		Domain:    domain,
		Status:    "running",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, err := DB.ExecContext(ctx,
		"INSERT INTO scans (id, domain, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
		scan.ID, scan.Domain, scan.Status, scan.CreatedAt, scan.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}

	return scan, nil
}

func GetScan(ctx context.Context, id string) (*Scan, error) {
	scan := &Scan{}
	err := DB.QueryRowContext(ctx,
		"SELECT id, domain, status, summary, created_at, updated_at FROM scans WHERE id = ?", id).
		Scan(&scan.ID, &scan.Domain, &scan.Status, &scan.Summary, &scan.CreatedAt, &scan.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scan: %w", err)
	}

	return scan, nil
}

func GetRecentScans(ctx context.Context, limit int) ([]Scan, error) {
	rows, err := DB.QueryContext(ctx,
		"SELECT id, domain, status, summary, created_at, updated_at FROM scans ORDER BY created_at DESC LIMIT ?", limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent scans: %w", err)
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var scan Scan
		if err := rows.Scan(&scan.ID, &scan.Domain, &scan.Status, &scan.Summary, &scan.CreatedAt, &scan.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		scans = append(scans, scan)
	}

	return scans, nil
}

func UpdateScanStatus(ctx context.Context, id, status, summary string) error {
	_, err := DB.ExecContext(ctx,
		"UPDATE scans SET status = ?, summary = ?, updated_at = ? WHERE id = ?",
		status, summary, time.Now(), id)
	return err
}

func CreateFinding(ctx context.Context, finding *Finding) error {
	_, err := DB.ExecContext(ctx,
		"INSERT INTO findings (id, scan_id, subdomain, risk, open_ports, tech, tech_version, outdated, headers) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		finding.ID, finding.ScanID, finding.Subdomain, finding.Risk, finding.OpenPorts, finding.Tech, finding.TechVersion, finding.Outdated, finding.Headers)

	if err != nil {
		return fmt.Errorf("failed to create finding: %w", err)
	}

	return nil
}

func GetFindingsByScanID(ctx context.Context, scanID string) ([]Finding, error) {
	rows, err := DB.QueryContext(ctx,
		"SELECT id, scan_id, subdomain, risk, open_ports, tech, tech_version, outdated, headers FROM findings WHERE scan_id = ?", scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var f Finding
		var outdated int
		if err := rows.Scan(&f.ID, &f.ScanID, &f.Subdomain, &f.Risk, &f.OpenPorts, &f.Tech, &f.TechVersion, &outdated, &f.Headers); err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}
		f.Outdated = outdated == 1
		findings = append(findings, f)
	}

	return findings, nil
}

func GetScanWithFindings(ctx context.Context, id string) (*Scan, []Finding, error) {
	scan, err := GetScan(ctx, id)
	if err != nil || scan == nil {
		return scan, nil, err
	}

	findings, err := GetFindingsByScanID(ctx, id)
	if err != nil {
		return scan, nil, err
	}

	return scan, findings, nil
}

func DeleteScan(ctx context.Context, id string) error {
	_, err := DB.ExecContext(ctx, "DELETE FROM findings WHERE scan_id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete findings: %w", err)
	}

	_, err = DB.ExecContext(ctx, "DELETE FROM scans WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete scan: %w", err)
	}

	return nil
}

func GetRiskCounts(ctx context.Context, scanID string) (critical, warning, safe int, err error) {
	err = DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM findings WHERE scan_id = ? AND risk = 'critical'", scanID).Scan(&critical)
	if err != nil {
		return
	}

	err = DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM findings WHERE scan_id = ? AND risk = 'warning'", scanID).Scan(&warning)
	if err != nil {
		return
	}

	err = DB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM findings WHERE scan_id = ? AND risk = 'safe'", scanID).Scan(&safe)
	if err != nil {
		return
	}

	return critical, warning, safe, nil
}

func FindScanByDomain(ctx context.Context, domain string) (*Scan, error) {
	scan := &Scan{}
	err := DB.QueryRowContext(ctx,
		"SELECT id, domain, status, summary, created_at, updated_at FROM scans WHERE domain = ? ORDER BY created_at DESC LIMIT 1", domain).
		Scan(&scan.ID, &scan.Domain, &scan.Status, &scan.Summary, &scan.CreatedAt, &scan.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find scan by domain: %w", err)
	}

	return scan, nil
}

func CountSubdomains(ctx context.Context, scanID string) (int, error) {
	var count int
	err := DB.QueryRowContext(ctx,
		"SELECT COUNT(DISTINCT subdomain) FROM findings WHERE scan_id = ?", scanID).Scan(&count)
	return count, err
}

func JSONToString(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func StringToJSON(s string) map[string]interface{} {
	var result map[string]interface{}
	json.Unmarshal([]byte(s), &result)
	return result
}
