package agent

const SystemPrompt = `You are a cybersecurity recon analyst. Given a domain, you will systematically map its external attack surface using your available tools. 

Run tools in this order:
1. enumerate_subdomains - Get all subdomains from crt.sh
2. For each subdomain: check_headers, identify_tech, check_ports
3. After all subdomains are processed, call generate_summary

Be thorough but efficient. Never skip a tool call.

Risk scoring rules:
- critical: outdated tech version detected OR port 8080/3000/5000/8443 open
- warning: unrecognized tech stack OR non-standard open port
- safe: only 80/443 open, no outdated tech detected

Always provide actionable findings with specific details.`

const EnumerateSubdomainsTool = `{
  "type": "function",
  "function": {
    "name": "enumerate_subdomains",
    "description": "Enumerate all subdomains for a given domain using the crt.sh public API",
    "parameters": {
      "type": "object",
      "properties": {
        "domain": {
          "type": "string",
          "description": "The root domain to enumerate subdomains for (e.g., 'tesla.com')"
        }
      },
      "required": ["domain"]
    }
  }
}`

const CheckHeadersTool = `{
  "type": "function",
  "function": {
    "name": "check_headers",
    "description": "Fetch HTTP headers from a given URL to identify server configuration",
    "parameters": {
      "type": "object",
      "properties": {
        "url": {
          "type": "string",
          "description": "The full URL to fetch headers from (e.g., 'https://api.tesla.com')"
        }
      },
      "required": ["url"]
    }
  }
}`

const IdentifyTechTool = `{
  "type": "function",
  "function": {
    "name": "identify_tech",
    "description": "Identify the technology stack and version from HTTP headers",
    "parameters": {
      "type": "object",
      "properties": {
        "headers": {
          "type": "object",
          "description": "Map of HTTP header keys to values"
        }
      },
      "required": ["headers"]
    }
  }
}`

const CheckPortsTool = `{
  "type": "function",
  "function": {
    "name": "check_ports",
    "description": "Check which common ports are open on a given host via TCP dial",
    "parameters": {
      "type": "object",
      "properties": {
        "host": {
          "type": "string",
          "description": "The hostname or IP to check ports on (e.g., 'api.tesla.com')"
        },
        "ports": {
          "type": "array",
          "items": {
            "type": "integer"
          },
          "description": "Array of port numbers to check (e.g., [80, 443, 8080, 8443, 3000, 5000])"
        }
      },
      "required": ["host", "ports"]
    }
  }
}`

const GenerateSummaryTool = `{
  "type": "function",
  "function": {
    "name": "generate_summary",
    "description": "Generate a markdown summary of all findings after scanning is complete",
    "parameters": {
      "type": "object",
      "properties": {
        "findings": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "subdomain": {"type": "string"},
              "risk": {"type": "string", "enum": ["safe", "warning", "critical"]},
              "open_ports": {"type": "array", "items": {"type": "integer"}},
              "tech": {"type": "string"},
              "tech_version": {"type": "string"},
              "outdated": {"type": "boolean"}
            }
          },
          "description": "Array of all findings from the scan"
        }
      },
      "required": ["findings"]
    }
  }
}`

var ToolSchemas = []string{
	EnumerateSubdomainsTool,
	CheckHeadersTool,
	IdentifyTechTool,
	CheckPortsTool,
	GenerateSummaryTool,
}

var ToolNames = []string{
	"enumerate_subdomains",
	"check_headers",
	"identify_tech",
	"check_ports",
	"generate_summary",
}
