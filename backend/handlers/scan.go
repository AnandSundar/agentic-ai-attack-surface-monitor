package handlers

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"attack-surface-monitor/backend/agent"
	"attack-surface-monitor/backend/db"
)

var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// ScanRequest represents a scan request
type ScanRequest struct {
	Domain string `json:"domain"`
}

// ScanResponse represents a scan response
type ScanResponse struct {
	ScanID string `json:"scan_id"`
	Status string `json:"status"`
}

// RecentScan represents a recent scan for listing
type RecentScan struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// StartScan handles POST /api/scan
func StartScan(c *fiber.Ctx) error {
	var req ScanRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate domain
	domain := cleanDomain(req.Domain)
	if domain == "" || !isValidDomain(domain) {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid domain format",
		})
	}

	// Create scan record
	scanID := uuid.New().String()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	scan, err := db.CreateScan(ctx, scanID, domain)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create scan",
		})
	}

	// Start agent in background
	go func() {
		agent.SetBroadcastFunc(func(scanID string, event agent.WSEvent) {
			BroadcastToScan(scanID, WSEvent(event))
		})
		agentCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		agent.RunAgent(agentCtx, scanID, domain)
	}()

	return c.Status(http.StatusAccepted).JSON(ScanResponse{
		ScanID: scanID,
		Status: scan.Status,
	})
}

// GetScan handles GET /api/scan/:id
func GetScan(c *fiber.Ctx) error {
	scanID := c.Params("id")
	if scanID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Scan ID required",
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	scan, findings, err := db.GetScanWithFindings(ctx, scanID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get scan",
		})
	}

	if scan == nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Scan not found",
		})
	}

	// Convert findings to frontend format (open_ports as array)
	findingsList := make([]map[string]interface{}, len(findings))
	for i, f := range findings {
		var openPorts []int
		if f.OpenPorts != "" {
			json.Unmarshal([]byte(f.OpenPorts), &openPorts)
		}
		var headers map[string]string
		if f.Headers != "" {
			json.Unmarshal([]byte(f.Headers), &headers)
		}
		findingsList[i] = map[string]interface{}{
			"id":           f.ID,
			"scan_id":      f.ScanID,
			"subdomain":    f.Subdomain,
			"risk":         f.Risk,
			"open_ports":   openPorts,
			"tech":         f.Tech,
			"tech_version": f.TechVersion,
			"outdated":     f.Outdated,
			"headers":      headers,
		}
	}

	// Return in format expected by frontend (ScanWithFindings)
	return c.JSON(fiber.Map{
		"id":         scan.ID,
		"domain":     scan.Domain,
		"status":     scan.Status,
		"summary":    scan.Summary,
		"created_at": scan.CreatedAt,
		"updated_at": scan.UpdatedAt,
		"findings":   findingsList,
	})
}

// ListScans handles GET /api/scans
func ListScans(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	scans, err := db.GetRecentScans(ctx, 20)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get scans",
		})
	}

	recentScans := make([]RecentScan, len(scans))
	for i, scan := range scans {
		recentScans[i] = RecentScan{
			ID:        scan.ID,
			Domain:    scan.Domain,
			Status:    scan.Status,
			CreatedAt: scan.CreatedAt,
		}
	}

	return c.JSON(recentScans)
}

// HealthCheck handles GET /health
func HealthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
	})
}

func cleanDomain(domain string) string {
	// Remove protocol if present
	domain = removeProtocol(domain)
	// Remove www. prefix
	domain = removeWWW(domain)
	// Remove trailing slash and path
	if idx := findSlash(domain); idx != -1 {
		domain = domain[:idx]
	}
	// Remove port if present
	if idx := findColon(domain); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}

func removeProtocol(domain string) string {
	if len(domain) > 8 {
		if domain[:8] == "https://" {
			return domain[8:]
		}
	}
	if len(domain) > 7 {
		if domain[:7] == "http://" {
			return domain[7:]
		}
	}
	return domain
}

func removeWWW(domain string) string {
	if len(domain) > 4 {
		if domain[:4] == "www." {
			return domain[4:]
		}
	}
	return domain
}

func findSlash(domain string) int {
	for i, c := range domain {
		if c == '/' {
			return i
		}
	}
	return -1
}

func findColon(domain string) int {
	for i, c := range domain {
		if c == ':' {
			return i
		}
	}
	return -1
}

func isValidDomain(domain string) bool {
	if len(domain) < 4 || len(domain) > 253 {
		return false
	}

	if !domainRegex.MatchString(domain) {
		return false
	}

	// Check for valid TLD
	parts := splitDomain(domain)
	if len(parts) < 2 {
		return false
	}

	// TLD should be at least 2 characters
	if len(parts[len(parts)-1]) < 2 {
		return false
	}

	// Try to resolve the domain (basic check)
	_, err := net.LookupHost(domain)
	if err != nil {
		// Still allow unknown domains - this is just a basic validation
		// The crt.sh API will handle actual resolution
	}

	return true
}

func splitDomain(domain string) []string {
	var parts []string
	var current string
	for _, c := range domain {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
