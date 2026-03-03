package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/sashabaranov/go-openai"

	"attack-surface-monitor/backend/db"
)

var (
	openAIClient  *openai.Client
	toolCallLimit = 30
	broadcastFunc func(scanID string, event WSEvent)
)

// WSEvent represents a WebSocket event
type WSEvent struct {
	Type      string      `json:"type"`
	Message   string      `json:"message,omitempty"`
	Tool      string      `json:"tool,omitempty"`
	Input     interface{} `json:"input,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Subdomain string      `json:"subdomain,omitempty"`
	Risk      string      `json:"risk,omitempty"`
	Details   interface{} `json:"details,omitempty"`
	Summary   string      `json:"summary,omitempty"`
}

// InitOpenAI initializes the OpenAI client
func InitOpenAI(apiKey string) {
	openAIClient = openai.NewClient(apiKey)
}

// SetBroadcastFunc sets the broadcast function for the agent
func SetBroadcastFunc(fn func(scanID string, event WSEvent)) {
	broadcastFunc = fn
}

// RunAgent runs the AI agent for a given scan
func RunAgent(ctx context.Context, scanID, domain string) {
	log.Printf("Starting agent for scan %s with domain %s", scanID, domain)

	broadcast(scanID, WSEvent{
		Type:    "agent_thought",
		Message: fmt.Sprintf("Starting attack surface scan for %s...", domain),
	})

	log.Printf("Agent %s: Calling enumerate_subdomains", scanID)

	// Get subdomains first
	broadcast(scanID, WSEvent{
		Type:  "tool_call",
		Tool:  "enumerate_subdomains",
		Input: map[string]string{"domain": domain},
	})

	subdomains, err := EnumerateSubdomains(ctx, domain)
	if err != nil {
		log.Printf("Agent %s: EnumerateSubdomains error: %v", scanID, err)
		broadcast(scanID, WSEvent{
			Type:    "error",
			Message: fmt.Sprintf("Failed to enumerate subdomains: %v", err),
		})
		updateScanStatus(scanID, "error", "")
		return
	}

	log.Printf("Agent %s: Found %d subdomains", scanID, len(subdomains))

	broadcast(scanID, WSEvent{
		Type: "tool_result",
		Tool: "enumerate_subdomains",
		Data: subdomains,
	})

	if len(subdomains) == 0 {
		broadcast(scanID, WSEvent{
			Type:    "agent_thought",
			Message: "No subdomains found. Checking the root domain directly.",
		})
		subdomains = []string{domain}
	}

	broadcast(scanID, WSEvent{
		Type:    "agent_thought",
		Message: fmt.Sprintf("Found %d subdomains. Now analyzing each endpoint...", len(subdomains)),
	})

	// Process each subdomain
	findings := make([]FindingData, 0)
	var findingsMu sync.Mutex

	log.Printf("Agent %s: Processing %d subdomains", scanID, len(subdomains))

	for i, subdomain := range subdomains {
		log.Printf("Agent %s: Processing subdomain %d/%d: %s", scanID, i+1, len(subdomains), subdomain)

		// Rate limiting to avoid overwhelming targets
		if i > 0 && i%5 == 0 {
			time.Sleep(500 * time.Millisecond)
		}

		broadcast(scanID, WSEvent{
			Type:    "agent_thought",
			Message: fmt.Sprintf("Analyzing %s...", subdomain),
		})

		// Check headers
		log.Printf("Agent %s: Checking headers for %s", scanID, subdomain)
		broadcast(scanID, WSEvent{
			Type:  "tool_call",
			Tool:  "check_headers",
			Input: map[string]string{"url": subdomain},
		})

		headers, err := CheckHeaders(ctx, subdomain)
		if err != nil {
			broadcast(scanID, WSEvent{
				Type: "tool_result",
				Tool: "check_headers",
				Data: map[string]string{"error": err.Error()},
			})
			headers = make(map[string]string)
		}

		broadcast(scanID, WSEvent{
			Type: "tool_result",
			Tool: "check_headers",
			Data: headers,
		})

		// Identify tech
		broadcast(scanID, WSEvent{
			Type:  "tool_call",
			Tool:  "identify_tech",
			Input: map[string]interface{}{"headers": headers},
		})

		techInfo, err := IdentifyTech(ctx, headers)
		if err != nil {
			techInfo = &TechInfo{Tech: "Unknown", Version: "", Outdated: false}
		}

		broadcast(scanID, WSEvent{
			Type: "tool_result",
			Tool: "identify_tech",
			Data: techInfo,
		})

		// Check ports
		broadcast(scanID, WSEvent{
			Type: "tool_call",
			Tool: "check_ports",
			Input: map[string]interface{}{
				"host":  subdomain,
				"ports": []int{80, 443, 8080, 8443, 3000, 5000},
			},
		})

		portResults, err := CheckPorts(ctx, subdomain, []int{80, 443, 8080, 8443, 3000, 5000})
		var openPorts []int
		if err != nil {
			openPorts = []int{}
		} else {
			openPorts = portResults["open"]
		}

		broadcast(scanID, WSEvent{
			Type: "tool_result",
			Tool: "check_ports",
			Data: map[string][]int{"open": openPorts},
		})

		// Determine risk
		risk := DetermineRisk(openPorts, techInfo)

		finding := FindingData{
			Subdomain:   subdomain,
			Risk:        risk,
			OpenPorts:   openPorts,
			Tech:        techInfo.Tech,
			TechVersion: techInfo.Version,
			Outdated:    techInfo.Outdated,
		}

		findingsMu.Lock()
		findings = append(findings, finding)
		findingsMu.Unlock()

		// Save finding to database
		saveFinding(ctx, scanID, &finding, headers)

		// Broadcast finding
		broadcast(scanID, WSEvent{
			Type:      "finding",
			Subdomain: subdomain,
			Risk:      risk,
			Details:   finding,
		})
	}

	// Generate summary
	broadcast(scanID, WSEvent{
		Type:  "tool_call",
		Tool:  "generate_summary",
		Input: map[string]interface{}{"findings": findings},
	})

	summary, err := GenerateSummary(ctx, findings)
	if err != nil {
		summary = fmt.Sprintf("## Summary\n\nFailed to generate summary: %v", err)
	}

	broadcast(scanID, WSEvent{
		Type:    "complete",
		Summary: summary,
	})

	// Update scan status in database
	updateScanStatus(scanID, "complete", summary)

	log.Printf("Agent completed for scan %s", scanID)
}

func broadcast(scanID string, event WSEvent) {
	if broadcastFunc != nil {
		broadcastFunc(scanID, event)
	}
}

func updateScanStatus(scanID, status, summary string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.UpdateScanStatus(ctx, scanID, status, summary); err != nil {
		log.Printf("Failed to update scan status: %v", err)
	}
}

func saveFinding(ctx context.Context, scanID string, finding *FindingData, headers map[string]string) {
	headersJSON, _ := json.Marshal(headers)
	openPortsJSON, _ := json.Marshal(finding.OpenPorts)

	dbFinding := &db.Finding{
		ID:          fmt.Sprintf("%s-%s", scanID, finding.Subdomain),
		ScanID:      scanID,
		Subdomain:   finding.Subdomain,
		Risk:        finding.Risk,
		OpenPorts:   string(openPortsJSON),
		Tech:        finding.Tech,
		TechVersion: finding.TechVersion,
		Outdated:    finding.Outdated,
		Headers:     string(headersJSON),
	}

	if err := db.CreateFinding(ctx, dbFinding); err != nil {
		log.Printf("Failed to save finding: %v", err)
	}
}
