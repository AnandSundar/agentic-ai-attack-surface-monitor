# 🌐 Agentic AI Attack Surface Monitor

A web application where a user types in a company's website domain and an AI agent automatically scans its external **attack surface** (all the publicly visible entry points a hacker could try to exploit), discovers subdomains, checks software versions, tests open network ports, identifies outdated technology, and scores each finding by risk level. Results stream live to a visual dashboard with an interactive graph, data table, and risk summary.

[![Go](https://img.shields.io/badge/Go-1.22-blue?style=flat&logo=go)](https://go.dev/)
[![Next.js](https://img.shields.io/badge/Next.js-14-black?style=flat&logo=next.js)](https://nextjs.org/)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o-green?style=flat&logo=openai)](https://openai.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat)](https://opensource.org/licenses/MIT)
[![Deploy on Vercel](https://img.shields.io/badge/Deploy-Vercel-black?style=flat&logo=vercel)](https://vercel.com)
[![Deploy on fly.io](https://img.shields.io/badge/Deploy-fly.io-purple?style=flat&logo=fly.io)](https://fly.io)

![Dashboard Preview](./docs/preview.gif)
> *Live scan in progress — subdomains streaming in real time*

[🚀 Live Demo](#) | [📖 Docs](#) | [🐛 Report Bug](#)

---

## Why This Exists

Every company with a website has an **attack surface** — the collection of all the digital doors and windows that face the public internet. Just like a building with more entrances has more potential points of entry for intruders, a company with more web addresses, servers, and open network ports has more places where attackers might find vulnerabilities. Large organizations can have thousands of these public-facing entry points, and keeping track of them manually is nearly impossible.

This is why companies pay millions of dollars each year for **attack surface management** tools that automatically discover and monitor their external digital footprint. These tools help security teams find exposed services, outdated software, and misconfigurations before attackers do.

Traditionally, this kind of security scanning required expensive enterprise tools or manual expertise. This project demonstrates how **AI agents** can automate the entire reconnaissance process — from discovering subdomains to analyzing each one for vulnerabilities — using large language models that can reason about security findings in real-time. This project demonstrates that capability in a working, open-source tool.

---

## Features

| Feature | Description |
|---|---|
| AI-Powered Recon Agent | An autonomous AI agent that uses OpenAI's GPT-4o to plan and execute security reconnaissance tasks, deciding which tools to run based on previous results |
| Real-Time Streaming Dashboard | Live updates via WebSocket showing scan progress, new findings, and risk scores as they happen |
| Subdomain Enumeration | Discovers all subdomains associated with a target domain using Certificate Transparency logs (crt.sh API) |
| HTTP Header Analysis | Inspects HTTP response headers to identify security configurations, server types, and potential misconfigurations |
| Tech Stack Fingerprinting | Identifies the technology stack (web server, framework, programming language) running on each discovered endpoint |
| Open Port Detection | Tests common ports (80, 443, 8080, 8443, 3000, 5000) to find accessible services |
| Automated Risk Scoring | Assigns risk levels (Safe, Warning, Critical) based on detected technology and open ports |
| Interactive Attack Graph | Visual network graph showing the root domain and all discovered subdomains, color-coded by risk level |
| Scan History | Stores all scan results in SQLite for later review and comparison |
| Zero-Config Demo Mode | Pre-fills tesla.com for instant demonstration without requiring an API key |

---

## How It Works

1. **You enter a domain** — Type any domain like tesla.com into the input field and click "Start Scan"

2. **The AI agent wakes up** — An autonomous agent powered by OpenAI GPT-4o receives your request and begins planning the reconnaissance

3. **The agent discovers subdomains** — It queries Certificate Transparency logs to find all subdomains associated with your target domain

4. **The agent inspects each subdomain** — For every subdomain found, it checks HTTP headers, identifies the technology stack, and tests for open ports

5. **Risk levels are assigned** — Each finding is scored as Safe, Warning, or Critical based on the technology detected and services exposed

6. **Results stream to your screen** — All findings appear in real-time on the dashboard via WebSocket

7. **You get a full attack surface map** — An interactive graph visualizes the entire attack surface, showing how each endpoint relates to the root domain

```
┌─────────────────────────────────────────────────────────────┐
│                        BROWSER                              │
│         Next.js Frontend  (Vercel)                          │
│   ┌──────────────┐    ┌──────────────┐                      │
│   │  Domain Input│    │  Live Feed + │                      │
│   │    Form      │    │  Attack Graph│                      │
│   └──────┬───────┘    └──────▲───────┘                      │
│          │ HTTP POST         │ WebSocket Stream              │
└──────────┼───────────────────┼──────────────────────────────┘
           │                   │
┌──────────▼───────────────────┴──────────────────────────────┐
│                   GO BACKEND  (fly.io)                       │
│                   Fiber v2 REST + WebSocket API              │
│   ┌────────────────────────────────────────────────────┐    │
│   │              AI AGENT (go-openai)                  │    │
│   │  enumerate_subdomains → check_headers →            │    │
│   │  identify_tech → check_ports → generate_summary   │    │
│   └──────┬──────────────────────────┬──────────────────┘    │
│          │                          │                        │
│   ┌──────▼──────┐          ┌────────▼────────┐              │
│   │  SQLite DB  │          │  External APIs  │              │
│   │  (scans +   │          │  crt.sh  OpenAI │              │
│   │  findings)  │          │  TCP Dials      │              │
│   └─────────────┘          └─────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

---

## Risk Scoring Explained

Every finding receives a risk level that helps prioritize remediation efforts. The system evaluates each subdomain based on what technology it runs and which network ports are accessible.

| Risk Level | Color | Trigger Conditions |
|---|---|---|
| 🔴 Critical | #ff4d4d | Outdated software version detected OR unusual port open (8080, 3000, 5000) |
| 🟡 Warning  | #f5c542 | Unrecognized tech stack OR non-standard configuration found |
| 🟢 Safe     | #a0d2eb | Only standard ports (80/443) open, no outdated tech detected |

```go
risk_score = (critical_count × 3) + (warning_count × 1)
```

The risk score helps prioritize response:

- **Score 0**: No findings — the attack surface appears clean
- **Score 1–5**: Low risk — minor issues to monitor during routine security reviews
- **Score 6–15**: Medium risk — several concerning findings that warrant investigation
- **Score 15+**: High risk — significant exposure requiring immediate attention

---

## Tech Stack Deep Dive

| Layer | Technology | Version | Why This Choice |
|---|---|---|---|
| Backend Framework | Fiber | v2.52.0 | High-performance Go web framework with built-in WebSocket support; 10x faster than Express.js |
| Language | Go | 1.22 | Compiled language ideal for concurrent network operations; excellent for parallel subdomain scanning |
| LLM SDK | go-openai | v1.20.3 | Official OpenAI Go client with function calling support for tool-use pattern |
| Agent Pattern | Tool Calling | - | AI decides which recon tools to run sequentially based on results |
| Database | SQLite | modernc.org | Embedded database requiring no separate server; perfect for single-instance deployments |
| ORM/Query | glebarez/sqlite | v1.11.0 | Pure Go SQLite driver with excellent performance |
| Frontend Framework | Next.js | 14 | React framework with App Router; automatic optimization and SSR support |
| UI Library | shadcn/ui | latest | Accessible, composable component library built on Radix UI primitives |
| Styling | Tailwind CSS | latest | Utility-first CSS framework enabling rapid UI development |
| Animations | Framer Motion | latest | Declarative animation library for smooth transitions |
| Graph Visualization | Nivo (@nivo/network) | latest | Beautiful, responsive SVG/Canvas charts with React integration |
| Data Tables | TanStack Table | v8 | Headless UI for building powerful data tables with sorting and filtering |
| Frontend Hosting | Vercel | - | Zero-config deployment with automatic SSL and edge network |
| Backend Hosting | fly.io | - | Containerized deployment with global distribution and automatic scaling |

The choice of Go for the backend was deliberate. While Python is the traditional language for security tools, Go offers superior performance for network-intensive operations. The backend performs many parallel network calls — querying APIs, dialing TCP ports, and fetching HTTP headers — all simultaneously. Go's lightweight goroutines handle thousands of concurrent connections with minimal memory overhead, making it ideal for scanning hundreds of subdomains in parallel. Combined with Fiber's efficient HTTP handling, the backend can process scans significantly faster than a Node.js or Python equivalent.

---

## API Reference

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| POST | /api/scan | Start a new scan for a domain | None |
| GET | /api/scan/:id | Get scan results with all findings | None |
| GET | /api/scans | List recent scans | None |
| GET | /ws/scan/:id | WebSocket for real-time scan updates | None |
| GET | /health | Health check endpoint | None |

<details>
<summary>POST /api/scan — Example</summary>

**Request:**
```json
{
  "domain": "example.com"
}
```

**Response:**
```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "running"
}
```
</details>

<details>
<summary>GET /api/scan/:id — Example</summary>

**Response:**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "domain": "example.com",
  "status": "complete",
  "summary": "## Attack Surface Summary\n\nFound 5 subdomains...",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:35:00Z",
  "findings": [
    {
      "id": "scan1-www.example.com",
      "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "subdomain": "www.example.com",
      "risk": "safe",
      "open_ports": [80, 443],
      "tech": "nginx",
      "tech_version": "1.24.0",
      "outdated": false,
      "headers": {
        "server": "nginx/1.24.0"
      }
    }
  ]
}
```
</details>

<details>
<summary>GET /api/scans — Example</summary>

**Response:**
```json
[
  {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "domain": "example.com",
    "status": "complete",
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```
</details>

<details>
<summary>GET /ws/scan/:id — Example</summary>

**WebSocket Connection:** `wss://your-backend.com/ws/scan/a1b2c3d4-e5f6-7890-abcd-ef1234567890`

The server sends JSON events as the scan progresses. See WebSocket Event Schema below.
</details>

---

## WebSocket Event Schema

**WebSocket** is a technology that enables real-time, two-way communication between the browser and server — think of it as a phone call where both parties can send messages instantly, rather than sending letters and waiting for responses.

| Event Type | Color in UI | Meaning |
|---|---|---|
| agent_thought | #a28089 italic | The AI is reasoning about its next step |
| tool_call | #a0d2eb | The agent is about to run a recon tool |
| tool_result | #d0bdf4 | A tool has returned data |
| finding | risk color | A subdomain has been analyzed |
| complete | #8458B3 bold | Scan is finished |
| error | #ff4d4d | Something went wrong |

**agent_thought Event:**
```json
{
  "type": "agent_thought",
  "message": "Starting attack surface scan for tesla.com..."
}
```

**tool_call Event:**
```json
{
  "type": "tool_call",
  "tool": "enumerate_subdomains",
  "input": {
    "domain": "tesla.com"
  }
}
```

**tool_result Event:**
```json
{
  "type": "tool_result",
  "tool": "enumerate_subdomains",
  "data": ["www.tesla.com", "shop.tesla.com", "investor.tesla.com"]
}
```

**finding Event:**
```json
{
  "type": "finding",
  "subdomain": "www.tesla.com",
  "risk": "safe",
  "details": {
    "subdomain": "www.tesla.com",
    "risk": "safe",
    "open_ports": [80, 443],
    "tech": "cloudflare",
    "outdated": false
  }
}
```

**complete Event:**
```json
{
  "type": "complete",
  "summary": "## Attack Surface Summary\n\nFound 12 subdomains..."
}
```

**error Event:**
```json
{
  "type": "error",
  "message": "Failed to enumerate subdomains: timeout"
}
```

---

## Database Schema

### scans table

```sql
CREATE TABLE scans (
    id          TEXT PRIMARY KEY,          -- Unique UUID for this scan
    domain      TEXT NOT NULL,             -- The target domain (e.g., tesla.com)
    status      TEXT NOT NULL DEFAULT 'running',  -- 'running', 'complete', or 'error'
    summary     TEXT,                      -- AI-generated markdown summary of findings
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,  -- When the scan started
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP   -- Last status change
);
```

### findings table

```sql
CREATE TABLE findings (
    id          TEXT PRIMARY KEY,          -- Composite key: scan_id-subdomain
    scan_id     TEXT NOT NULL,             -- Foreign key to scans.id
    subdomain   TEXT NOT NULL,             -- Discovered subdomain
    risk        TEXT NOT NULL,             -- 'safe', 'warning', or 'critical'
    open_ports  TEXT,                     -- JSON array of open port numbers
    tech        TEXT,                      -- Identified technology (e.g., 'nginx')
    tech_version TEXT,                     -- Detected version (e.g., '1.24.0')
    outdated    INTEGER DEFAULT 0,         -- 1 if outdated software detected
    headers     TEXT,                      -- JSON object of HTTP headers
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
```

```
┌─────────────┐       ┌─────────────┐
│    scans     │       │  findings   │
├─────────────┤       ├─────────────┤
│ id (PK)     │──┐    │ id (PK)     │
│ domain      │  │    │ scan_id (FK)│──< (1 scan has many findings)
│ status      │  │    │ subdomain   │
│ summary     │  │    │ risk        │
│ created_at  │  │    │ open_ports  │
│ updated_at  │──┘    │ tech        │
└─────────────┘       │ ...         │
                     └─────────────┘
```

---

## Color Palette & Design System

| Name | Hex | Used For |
|---|---|---|
| Ice Cold | #a0d2eb | Accents, safe risk, links, graph safe nodes |
| Freeze Purple | #e5eaf5 | Card backgrounds, body text |
| Medium Purple | #d0bdf4 | Borders, badges, secondary text |
| Purple Pain | #8458B3 | Primary buttons, CTAs, root graph node |
| Heavy Purple | #a28089 | Muted text, disabled states |
| Background | #0d0d14 | Page background |

> 💡 **Design Note:** The gradient used on the app title blends Ice Cold → Purple Pain, symbolizing the transition from surface-level visibility to deep threat awareness.

---

## Local Development Setup

Follow these steps to get the project running on your local machine.

### Prerequisites

- **Go 1.22+** — Download from https://go.dev/dl/
- **Node.js 18+** — Download from https://nodejs.org/
- **OpenAI API Key** — Get one from https://platform.openai.com/api-keys

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/agentic-ai-attack-surface-monitor.git
cd agentic-ai-attack-surface-monitor
```

### Step 2: Backend Setup

Navigate to the backend directory:

```bash
cd backend
```

Create a `.env` file with your OpenAI API key:

```bash
cp .env.example .env
# Edit .env and set OPENAI_API_KEY=your_openai_key_here
```

Run the backend server:

```bash
go run main.go
```

The backend will start on http://localhost:8080

### Step 3: Frontend Setup

Open a new terminal and navigate to the frontend directory:

```bash
cd frontend
```

Install dependencies:

```bash
npm install
```

Create a `.env.local` file:

```bash
cp .env.example .env.local
```

Start the development server:

```bash
npm run dev
```

### Step 4: Open in Browser

Navigate to http://localhost:3000 to see the application.

> 💡 **No OpenAI key?** Click the "Try Demo" button on the home page to see a pre-loaded scan result without any API calls.

---

## Deployment Guide

### Frontend → Vercel

1. Push your code to a GitHub repository

2. Go to https://vercel.com and import the repository

3. Configure the project:
   - Framework Preset: Next.js
   - Build Command: `npm run build`
   - Output Directory: `.next`

4. Add environment variables:
   ```
   NEXT_PUBLIC_API_URL=https://your-backend.fly.dev
   NEXT_PUBLIC_WS_URL=wss://your-backend.fly.dev
   ```

5. Deploy!

### Backend → fly.io

1. Install the flyctl CLI:

```bash
npm install -g flyctl
```

2. Authenticate:

```bash
flyctl auth login
```

3. Navigate to the backend directory:

```bash
cd backend
```

4. Launch the app:

```bash
flyctl launch
```

5. Set the OpenAI API key as a secret:

```bash
flyctl secrets set OPENAI_API_KEY=your_openai_key_here
```

6. Scale the app (optional, for production):

```bash
flyctl scale memory 512
flyctl scale cpu 2
```

Your backend will be available at `https://your-app-name.fly.dev`

---

## Security Considerations

This section explains how the application was built with security best practices.

| Security Control | Implementation | Why It Matters |
|---|---|---|
| Rate limiting | Scans are limited to prevent abuse | Prevents resource exhaustion and ensures fair usage |
| No credentials stored | OpenAI key stays server-side, never exposed to browser | API keys cannot be stolen from the client |
| Input validation | Domain format is validated before any network calls | Prevents injection attacks and ensures valid targets |
| Timeout protection | All HTTP and TCP calls have 5-second timeouts | Prevents hanging connections and DoS |
| CORS policy | Only the frontend URL is whitelisted | Prevents unauthorized cross-origin requests |
| Passive recon only | Tool only reads publicly available information | Legal and ethical — never attempts to exploit anything |

---

## Roadmap

| Status | Feature |
|---|---|
| ✅ | Subdomain enumeration via crt.sh |
| ✅ | HTTP header analysis |
| ✅ | Tech stack fingerprinting |
| ✅ | Open port detection |
| ✅ | Risk scoring |
| ✅ | Live WebSocket streaming |
| ✅ | Attack surface graph |
| ✅ | Scan history |
| ⬜ | DNS record analysis (MX, TXT, SPF) |
| ⬜ | Screenshot capture per subdomain |
| ⬜ | CVE lookup for detected tech versions |
| ⬜ | PDF export of scan report |
| ⬜ | Slack/webhook notifications |
| ⬜ | User authentication + scan history per user |
| ⬜ | Rate limiting dashboard |

---

## Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

Please read [CONTRIBUTING.md](./CONTRIBUTING.md) for details on our code of conduct and development process.

---

## License

MIT License — see the [LICENSE](./LICENSE) file for details.

---

## Author

[Your Name]()

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/yourusername)
[![GitHub](https://img.shields.io/badge/GitHub-333?style=flat&logo=github)](https://github.com/yourusername)
[![Portfolio](https://img.shields.io/badge/Portfolio-Web-8458B3?style=flat&logo=vercel)](https://yourportfolio.com)

Built with Go, Next.js, and OpenAI — to demonstrate what modern AI-powered security tooling looks like in practice.
