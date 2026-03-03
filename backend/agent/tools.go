package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// EnumerateSubdomains uses the crt.sh API to find subdomains
func EnumerateSubdomains(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "AttackSurfaceMonitor/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from crt.sh: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var records []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return nil, fmt.Errorf("failed to decode crt.sh response: %w", err)
	}

	subdomainMap := make(map[string]bool)
	for _, record := range records {
		names := strings.Split(record.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			// Only include subdomains of the target domain
			if strings.HasSuffix(name, "."+domain) || name == domain {
				subdomainMap[name] = true
			}
		}
	}

	subdomains := make([]string, 0, len(subdomainMap))
	for subdomain := range subdomainMap {
		subdomains = append(subdomains, subdomain)
	}

	return subdomains, nil
}

// CheckHeaders fetches HTTP headers from a URL
func CheckHeaders(ctx context.Context, url string) (map[string]string, error) {
	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "AttackSurfaceMonitor/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		// Try HTTP if HTTPS fails
		if strings.HasPrefix(url, "https://") {
			url = strings.Replace(url, "https://", "http://", 1)
			req, err = http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create request: %w", err)
			}
			req.Header.Set("User-Agent", "AttackSurfaceMonitor/1.0")
			resp, err = httpClient.Do(req)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch headers: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to fetch headers: %w", err)
		}
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	return headers, nil
}

// KnownTech holds technology detection patterns
type KnownTech struct {
	Names    []string
	Header   string
	Prefixes []string
	Outdated map[string]bool
}

var knownTechs = []KnownTech{
	{
		Names:    []string{"Apache"},
		Header:   "Server",
		Prefixes: []string{"Apache"},
		Outdated: map[string]bool{
			"2.4.0":  true,
			"2.4.1":  true,
			"2.4.2":  true,
			"2.4.3":  true,
			"2.4.4":  true,
			"2.4.5":  true,
			"2.4.6":  true,
			"2.4.7":  true,
			"2.4.8":  true,
			"2.4.9":  true,
			"2.4.10": true,
			"2.4.11": true,
			"2.4.12": true,
			"2.4.13": true,
			"2.4.14": true,
			"2.4.15": true,
			"2.4.16": true,
			"2.4.17": true,
			"2.4.18": true,
			"2.4.19": true,
			"2.4.20": true,
			"2.4.21": true,
			"2.4.22": true,
			"2.4.23": true,
			"2.4.24": true,
			"2.4.25": true,
			"2.4.26": true,
			"2.4.27": true,
			"2.4.28": true,
			"2.4.29": true,
			"2.4.30": true,
			"2.4.31": true,
			"2.4.32": true,
			"2.4.33": true,
			"2.4.34": true,
			"2.4.35": true,
			"2.4.36": true,
			"2.4.37": true,
			"2.4.38": true,
		},
	},
	{
		Names:    []string{"Nginx"},
		Header:   "Server",
		Prefixes: []string{"nginx"},
		Outdated: map[string]bool{
			"0.7.0": true,
			"0.7.1": true,
			"0.7.2": true,
			"0.7.3": true,
			"0.7.4": true,
			"0.7.5": true,
			"0.7.6": true,
			"0.7.7": true,
			"0.7.8": true,
			"0.7.9": true,
			"0.8.0": true,
			"0.8.1": true,
			"0.8.2": true,
			"0.8.3": true,
			"0.8.4": true,
			"0.8.5": true,
			"0.8.6": true,
			"0.8.7": true,
			"0.8.8": true,
			"0.8.9": true,
			"1.0.0": true,
			"1.0.1": true,
			"1.0.2": true,
			"1.0.3": true,
			"1.0.4": true,
			"1.0.5": true,
			"1.0.6": true,
			"1.0.7": true,
			"1.0.8": true,
			"1.0.9": true,
			"1.1.0": true,
			"1.1.1": true,
			"1.1.2": true,
			"1.1.3": true,
			"1.1.4": true,
			"1.1.5": true,
			"1.1.6": true,
			"1.1.7": true,
			"1.1.8": true,
			"1.1.9": true,
			"1.2.0": true,
			"1.2.1": true,
			"1.2.2": true,
			"1.2.3": true,
			"1.2.4": true,
			"1.2.5": true,
			"1.2.6": true,
			"1.4.0": true,
			"1.4.1": true,
			"1.4.2": true,
			"1.4.3": true,
			"1.4.4": true,
			"1.4.5": true,
			"1.4.6": true,
		},
	},
	{
		Names:    []string{"Microsoft IIS", "IIS"},
		Header:   "Server",
		Prefixes: []string{"Microsoft-IIS"},
		Outdated: map[string]bool{
			"6.0": true,
			"7.0": true,
			"7.5": true,
			"8.0": true,
			"8.5": true,
		},
	},
	{
		Names:    []string{"Express"},
		Header:   "X-Powered-By",
		Prefixes: []string{"Express"},
		Outdated: map[string]bool{
			"3.0.0": true,
			"3.0.1": true,
			"3.0.2": true,
			"3.0.3": true,
			"3.0.4": true,
			"3.0.5": true,
			"3.0.6": true,
			"3.0.7": true,
			"3.0.8": true,
			"3.0.9": true,
			"4.0.0": true,
			"4.0.1": true,
			"4.0.2": true,
			"4.1.0": true,
			"4.1.1": true,
			"4.1.2": true,
			"4.2.0": true,
			"4.2.1": true,
			"4.2.2": true,
		},
	},
	{
		Names:    []string{"PHP"},
		Header:   "X-Powered-By",
		Prefixes: []string{"PHP"},
		Outdated: map[string]bool{
			"5.0.0":  true,
			"5.0.1":  true,
			"5.0.2":  true,
			"5.0.3":  true,
			"5.0.4":  true,
			"5.0.5":  true,
			"5.1.0":  true,
			"5.1.1":  true,
			"5.1.2":  true,
			"5.1.3":  true,
			"5.1.4":  true,
			"5.1.5":  true,
			"5.1.6":  true,
			"5.2.0":  true,
			"5.2.1":  true,
			"5.2.2":  true,
			"5.2.3":  true,
			"5.2.4":  true,
			"5.2.5":  true,
			"5.2.6":  true,
			"5.2.7":  true,
			"5.2.8":  true,
			"5.2.9":  true,
			"5.2.10": true,
			"5.2.11": true,
			"5.2.12": true,
			"5.2.13": true,
			"5.2.14": true,
			"5.2.15": true,
			"5.2.16": true,
			"5.2.17": true,
			"5.3.0":  true,
			"5.3.1":  true,
			"5.3.2":  true,
			"5.3.3":  true,
			"5.3.4":  true,
			"5.3.5":  true,
			"5.3.6":  true,
			"5.3.7":  true,
			"5.3.8":  true,
			"5.3.9":  true,
			"5.3.10": true,
			"5.3.11": true,
			"5.3.12": true,
			"5.3.13": true,
			"5.3.14": true,
			"5.3.15": true,
			"5.3.16": true,
			"5.3.17": true,
			"5.3.18": true,
			"5.3.19": true,
			"5.3.20": true,
			"5.3.21": true,
			"5.3.22": true,
			"5.3.23": true,
			"5.3.24": true,
			"5.3.25": true,
			"5.3.26": true,
			"5.3.27": true,
			"5.3.28": true,
			"5.3.29": true,
			"5.4.0":  true,
			"5.4.1":  true,
			"5.4.2":  true,
			"5.4.3":  true,
			"5.4.4":  true,
			"5.4.5":  true,
			"5.4.6":  true,
			"5.4.7":  true,
			"5.4.8":  true,
			"5.4.9":  true,
			"5.4.10": true,
			"5.4.11": true,
			"5.4.12": true,
			"5.4.13": true,
			"5.4.14": true,
			"5.4.15": true,
			"5.4.16": true,
			"5.4.17": true,
			"5.4.18": true,
			"5.4.19": true,
			"5.4.20": true,
			"5.4.21": true,
			"5.4.22": true,
			"5.4.23": true,
			"5.4.24": true,
			"5.4.25": true,
			"5.4.26": true,
			"5.4.27": true,
			"5.4.28": true,
			"5.4.29": true,
			"5.4.30": true,
			"5.4.31": true,
			"5.4.32": true,
			"5.4.33": true,
			"5.4.34": true,
			"5.4.35": true,
			"5.4.36": true,
			"5.4.37": true,
			"5.4.38": true,
			"5.4.39": true,
			"5.4.40": true,
			"5.4.41": true,
			"5.4.42": true,
			"5.4.43": true,
			"5.4.44": true,
			"5.4.45": true,
			"5.5.0":  true,
			"5.5.1":  true,
			"5.5.2":  true,
			"5.5.3":  true,
			"5.5.4":  true,
			"5.5.5":  true,
			"5.5.6":  true,
			"5.5.7":  true,
			"5.5.8":  true,
			"5.5.9":  true,
			"5.5.10": true,
			"5.5.11": true,
			"5.5.12": true,
			"5.5.13": true,
			"5.5.14": true,
			"5.5.15": true,
			"5.5.16": true,
			"5.5.17": true,
			"5.5.18": true,
			"5.5.19": true,
			"5.5.20": true,
			"5.5.21": true,
			"5.5.22": true,
			"5.5.23": true,
			"5.5.24": true,
			"5.5.25": true,
			"5.5.26": true,
			"5.5.27": true,
			"5.5.28": true,
			"5.5.29": true,
			"5.5.30": true,
			"5.5.31": true,
			"5.5.32": true,
			"5.5.33": true,
			"5.5.34": true,
			"5.5.35": true,
			"5.5.36": true,
			"5.5.37": true,
			"5.5.38": true,
		},
	},
	{
		Names:    []string{"Django"},
		Header:   "Server",
		Prefixes: []string{"WSGIServer", "gunicorn"},
		Outdated: map[string]bool{
			"1.0":  true,
			"1.1":  true,
			"1.2":  true,
			"1.3":  true,
			"1.4":  true,
			"1.5":  true,
			"1.6":  true,
			"1.7":  true,
			"1.8":  true,
			"1.9":  true,
			"1.10": true,
			"1.11": true,
		},
	},
	{
		Names:    []string{"Rails", "Ruby on Rails"},
		Header:   "X-Powered-By",
		Prefixes: []string{"Phusion_Passenger", "Rack"},
		Outdated: map[string]bool{
			"2.0.0":  true,
			"2.1.0":  true,
			"2.2.0":  true,
			"2.3.0":  true,
			"2.3.1":  true,
			"2.3.2":  true,
			"2.3.3":  true,
			"2.3.4":  true,
			"2.3.5":  true,
			"2.3.6":  true,
			"2.3.7":  true,
			"2.3.8":  true,
			"3.0.0":  true,
			"3.0.1":  true,
			"3.0.2":  true,
			"3.0.3":  true,
			"3.0.4":  true,
			"3.0.5":  true,
			"3.0.6":  true,
			"3.0.7":  true,
			"3.0.8":  true,
			"3.0.9":  true,
			"3.1.0":  true,
			"3.1.1":  true,
			"3.1.2":  true,
			"3.1.3":  true,
			"3.1.4":  true,
			"3.2.0":  true,
			"3.2.1":  true,
			"3.2.2":  true,
			"3.2.3":  true,
			"3.2.4":  true,
			"3.2.5":  true,
			"3.2.6":  true,
			"3.2.7":  true,
			"3.2.8":  true,
			"3.2.9":  true,
			"3.2.10": true,
			"3.2.11": true,
			"3.2.12": true,
			"3.2.13": true,
			"3.2.14": true,
			"3.2.15": true,
			"3.2.16": true,
			"3.2.17": true,
			"3.2.18": true,
			"3.2.19": true,
			"3.2.20": true,
			"3.2.21": true,
			"3.2.22": true,
			"4.0.0":  true,
			"4.0.1":  true,
			"4.0.2":  true,
			"4.0.3":  true,
			"4.0.4":  true,
			"4.0.5":  true,
			"4.0.6":  true,
			"4.0.7":  true,
			"4.0.8":  true,
			"4.0.9":  true,
			"4.0.10": true,
			"4.0.11": true,
			"4.1.0":  true,
			"4.1.1":  true,
			"4.1.2":  true,
			"4.1.3":  true,
			"4.1.4":  true,
			"4.1.5":  true,
			"4.1.6":  true,
			"4.1.7":  true,
			"4.1.8":  true,
			"4.1.9":  true,
			"4.1.10": true,
			"4.1.11": true,
			"4.1.12": true,
			"4.2.0":  true,
			"4.2.1":  true,
			"4.2.2":  true,
			"4.2.3":  true,
			"4.2.4":  true,
			"4.2.5":  true,
			"4.2.6":  true,
			"4.2.7":  true,
			"4.2.8":  true,
			"4.2.9":  true,
			"4.2.10": true,
		},
	},
	{
		Names:    []string{"AWS", "Amazon"},
		Header:   "Server",
		Prefixes: []string{"AmazonS3", "AmazonCloudFront"},
		Outdated: map[string]bool{},
	},
	{
		Names:    []string{"Cloudflare"},
		Header:   "Server",
		Prefixes: []string{"cloudflare"},
		Outdated: map[string]bool{},
	},
	{
		Names:    []string{"Vercel"},
		Header:   "Server",
		Prefixes: []string{"Vercel"},
		Outdated: map[string]bool{},
	},
	{
		Names:    []string{"Netlify"},
		Header:   "Server",
		Prefixes: []string{"Netlify"},
		Outdated: map[string]bool{},
	},
	{
		Names:    []string{"Node.js"},
		Header:   "X-Powered-By",
		Prefixes: []string{"Express"},
		Outdated: map[string]bool{},
	},
}

// IdentifyTech identifies technology stack from HTTP headers
type TechInfo struct {
	Tech     string `json:"tech"`
	Version  string `json:"version"`
	Outdated bool   `json:"outdated"`
}

func IdentifyTech(ctx context.Context, headers map[string]string) (*TechInfo, error) {
	if len(headers) == 0 {
		return &TechInfo{
			Tech:     "Unknown",
			Version:  "",
			Outdated: false,
		}, nil
	}

	for _, tech := range knownTechs {
		headerValue, exists := headers[tech.Header]
		if !exists {
			continue
		}

		for _, prefix := range tech.Prefixes {
			if strings.HasPrefix(strings.ToLower(headerValue), strings.ToLower(prefix)) {
				version := extractVersion(headerValue, prefix)
				isOutdated := false
				if version != "" {
					isOutdated = tech.Outdated[version]
				}

				return &TechInfo{
					Tech:     tech.Names[0],
					Version:  version,
					Outdated: isOutdated,
				}, nil
			}
		}
	}

	// Check Server header for unknown tech
	if server, exists := headers["Server"]; exists && server != "" {
		return &TechInfo{
			Tech:     server,
			Version:  "",
			Outdated: false,
		}, nil
	}

	return &TechInfo{
		Tech:     "Unknown",
		Version:  "",
		Outdated: false,
	}, nil
}

func extractVersion(headerValue, prefix string) string {
	rest := strings.TrimPrefix(headerValue, prefix)
	rest = strings.TrimSpace(rest)

	if rest == "" {
		return ""
	}

	// Try to extract version number
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) > 1 {
		version := strings.TrimSpace(parts[1])
		// Extract just the version number (e.g., "1.2.3" from "1.2.3 (Ubuntu)")
		versionParts := strings.Fields(version)
		if len(versionParts) > 0 {
			return versionParts[0]
		}
		return version
	}

	return ""
}

// CheckPorts checks which ports are open on a host
func CheckPorts(ctx context.Context, host string, ports []int) (map[string][]int, error) {
	openPorts := make([]int, 0)
	closedPorts := make([]int, 0)

	dialer := &net.Dialer{
		Timeout: 2 * time.Second,
	}

	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", host, port)

		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			closedPorts = append(closedPorts, port)
			continue
		}
		conn.Close()
		openPorts = append(openPorts, port)
	}

	return map[string][]int{
		"open":   openPorts,
		"closed": closedPorts,
	}, nil
}

// CheckPortsWithTLS checks if TLS is available on a port
func CheckPortsWithTLS(ctx context.Context, host string, ports []int) (map[string][]int, error) {
	openPorts := make([]int, 0)
	closedPorts := make([]int, 0)

	dialer := &net.Dialer{
		Timeout: 2 * time.Second,
	}

	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", host, port)

		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			// Try non-TLS
			var rawConn net.Conn
			rawConn, err = dialer.DialContext(ctx, "tcp", address)
			if err != nil {
				closedPorts = append(closedPorts, port)
				continue
			}
			rawConn.Close()
			openPorts = append(openPorts, port)
		} else {
			conn.Close()
			openPorts = append(openPorts, port)
		}
	}

	return map[string][]int{
		"open":   openPorts,
		"closed": closedPorts,
	}, nil
}

// DetermineRisk determines the risk level based on ports and tech
func DetermineRisk(openPorts []int, techInfo *TechInfo) string {
	criticalPorts := []int{8080, 8443, 3000, 5000}
	hasCriticalPort := false

	for _, p := range openPorts {
		for _, cp := range criticalPorts {
			if p == cp {
				hasCriticalPort = true
				break
			}
		}
	}

	if techInfo.Outdated || hasCriticalPort {
		return "critical"
	}

	// Check for non-standard ports
	standardPorts := []int{80, 443}
	hasNonStandardPort := false

	for _, p := range openPorts {
		isStandard := false
		for _, sp := range standardPorts {
			if p == sp {
				isStandard = true
				break
			}
		}
		if !isStandard {
			hasNonStandardPort = true
			break
		}
	}

	if techInfo.Tech == "Unknown" || hasNonStandardPort {
		return "warning"
	}

	return "safe"
}

// GenerateSummary creates a markdown summary of findings
func GenerateSummary(ctx context.Context, findings []FindingData) (string, error) {
	var buf bytes.Buffer

	buf.WriteString("## Attack Surface Summary\n\n")

	criticalCount := 0
	warningCount := 0
	safeCount := 0

	for _, f := range findings {
		switch f.Risk {
		case "critical":
			criticalCount++
		case "warning":
			warningCount++
		case "safe":
			safeCount++
		}
	}

	buf.WriteString(fmt.Sprintf("| Metric | Count |\n|--------|-------|\n"))
	buf.WriteString(fmt.Sprintf("| Total Subdomains | %d |\n", len(findings)))
	buf.WriteString(fmt.Sprintf("| Critical | %d |\n", criticalCount))
	buf.WriteString(fmt.Sprintf("| Warning | %d |\n", warningCount))
	buf.WriteString(fmt.Sprintf("| Safe | %d |\n\n", safeCount))

	if criticalCount > 0 {
		buf.WriteString("### Critical Findings\n\n")
		for _, f := range findings {
			if f.Risk == "critical" {
				buf.WriteString(fmt.Sprintf("- **%s**: ", f.Subdomain))
				if f.Tech != "" && f.Tech != "Unknown" {
					buf.WriteString(fmt.Sprintf("%s %s (outdated)", f.Tech, f.TechVersion))
				}
				if len(f.OpenPorts) > 0 {
					buf.WriteString(fmt.Sprintf(", open ports: %v", f.OpenPorts))
				}
				buf.WriteString("\n")
			}
		}
		buf.WriteString("\n")
	}

	if warningCount > 0 {
		buf.WriteString("### Warning Findings\n\n")
		for _, f := range findings {
			if f.Risk == "warning" {
				buf.WriteString(fmt.Sprintf("- **%s**: ", f.Subdomain))
				if f.Tech != "" && f.Tech != "Unknown" {
					buf.WriteString(fmt.Sprintf("%s", f.Tech))
				}
				if len(f.OpenPorts) > 0 {
					buf.WriteString(fmt.Sprintf(", open ports: %v", f.OpenPorts))
				}
				buf.WriteString("\n")
			}
		}
		buf.WriteString("\n")
	}

	if safeCount > 0 {
		buf.WriteString("### Safe Endpoints\n\n")
		for _, f := range findings {
			if f.Risk == "safe" {
				buf.WriteString(fmt.Sprintf("- **%s**: ", f.Subdomain))
				if f.Tech != "" && f.Tech != "Unknown" {
					buf.WriteString(fmt.Sprintf("%s", f.Tech))
				}
				buf.WriteString("\n")
			}
		}
		buf.WriteString("\n")
	}

	return buf.String(), nil
}

// FindingData represents a finding for the summary
type FindingData struct {
	Subdomain   string `json:"subdomain"`
	Risk        string `json:"risk"`
	OpenPorts   []int  `json:"open_ports"`
	Tech        string `json:"tech"`
	TechVersion string `json:"tech_version"`
	Outdated    bool   `json:"outdated"`
}
