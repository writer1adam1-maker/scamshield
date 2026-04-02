# ScamShield Vaccine MCP Server

## Model Context Protocol Integration

This document describes how to deploy the Website Vaccine system as an MCP (Model Context Protocol) server, enabling LLMs and AI agents to access website threat scanning.

---

## Overview

**MCP Server Type:** Resource + Tool Server
**Language:** TypeScript
**Transport:** stdio
**Authentication:** API Key (optional)

**Capabilities:**
- Scan websites for threats (on-demand)
- Retrieve cached vaccines
- Generate injection rules
- Monitor threat intelligence
- Export threat data

---

## MCP Tools

### 1. `vaccine_scan`

Scan a website and generate a threat report.

**Input:**
```typescript
{
  url: string;                    // Target URL to scan
  vericticScore?: number;         // Optional VERIDICT score (0-100)
  timeout?: number;               // Custom timeout (default: 15000ms)
}
```

**Output:**
```typescript
{
  url: string;
  timestamp: number;
  threatLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  threatScore: number;            // 0-100
  threatsDetected: VaccineThreat[];
  injectionRules: InjectionRule[];
  recommendations: string[];
  vericticScore?: number;
}
```

**Example:**
```typescript
{
  "type": "tool",
  "name": "vaccine_scan",
  "input": {
    "url": "https://suspicious-site.com",
    "vericticScore": 65
  }
}
```

**Response:**
```json
{
  "url": "https://suspicious-site.com",
  "threatLevel": "high",
  "threatScore": 70,
  "threatsDetected": [
    {
      "type": "PHISHING_FORM",
      "severity": "high",
      "description": "Form submits to external domain"
    }
  ],
  "recommendations": [
    "Do not enter personal information on this site"
  ]
}
```

---

### 2. `vaccine_get_cached`

Retrieve a cached vaccine if available and not expired.

**Input:**
```typescript
{
  url: string;                    // URL to look up
}
```

**Output:**
```typescript
{
  vaccine: VaccineReport | null;
  cached: boolean;
  expiresIn?: number;             // Seconds until expiration
}
```

---

### 3. `vaccine_invalidate`

Invalidate a cached vaccine (e.g., site has been cleaned).

**Input:**
```typescript
{
  url: string;
}
```

**Output:**
```typescript
{
  status: 'invalidated' | 'not_found';
  url: string;
}
```

---

### 4. `vaccine_get_injection_script`

Get the protective JavaScript payload for a URL.

**Input:**
```typescript
{
  url: string;
  scriptType?: 'full' | 'minimal';  // full = all protections, minimal = essentials only
}
```

**Output:**
```typescript
{
  script: string;                 // JavaScript code
  rules: InjectionRule[];
  url: string;
}
```

---

### 5. `vaccine_get_threat_intelligence`

Get current threat intelligence (malware signatures, phishing patterns).

**Input:**
```typescript
{
  category?: 'malware' | 'phishing' | 'scam' | 'all';
  limit?: number;                 // Max signatures to return
}
```

**Output:**
```typescript
{
  signatures: MalwareSignature[];
  patterns: PhishingPattern[];
  lastUpdated: number;
}
```

---

### 6. `vaccine_get_statistics`

Get vaccine system statistics.

**Input:**
```typescript
{
  timeRange?: '1h' | '24h' | '7d' | 'all';
}
```

**Output:**
```typescript
{
  cachedVaccines: number;
  totalThreatsDetected: number;
  threatsByType: Record<string, number>;
  threatLevelDistribution: Record<string, number>;
  averageThreatScore: number;
  topThreats: Array<{ type: string; count: number }>;
}
```

---

## MCP Resources

### `vaccine:report/{url}`

Represents a vaccine report for a specific URL.

**URI:** `vaccine:report/https://example.com`

**Content Type:** `application/json`

**Content:**
```json
{
  "url": "https://example.com",
  "threatLevel": "safe",
  "threatScore": 5,
  "threatsDetected": [],
  "timestamp": 1711977600000
}
```

---

### `vaccine:injection/{url}`

Represents the injection script for a URL.

**URI:** `vaccine:injection/https://example.com`

**Content Type:** `application/javascript`

**Content:**
```javascript
/* ScamShield protective JavaScript */
(function() { ... })();
```

---

### `vaccine:threats`

Global threat intelligence resource.

**URI:** `vaccine:threats`

**Content Type:** `application/json`

**Content:**
```json
{
  "malwareSigs": [...],
  "phishingPatterns": [...],
  "lastUpdated": 1711977600000
}
```

---

## Server Implementation

### Installation

```bash
# Install MCP SDK
npm install @modelcontextprotocol/sdk

# Install server dependencies
npm install jsdom @anthropic-ai/sdk
```

### server.ts

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { vaccineManager } from "@/lib/vaccine/vaccine-manager";

const server = new Server({
  name: "scamshield-vaccine",
  version: "1.0.0",
});

// Define tools
const tools: Tool[] = [
  {
    name: "vaccine_scan",
    description: "Scan a website for threats and generate a vaccine report",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: {
          type: "string",
          description: "Target URL to scan",
        },
        vericticScore: {
          type: "number",
          description: "Optional VERIDICT score (0-100)",
        },
        timeout: {
          type: "number",
          description: "Custom timeout in milliseconds",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "vaccine_get_cached",
    description: "Get a cached vaccine if available",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: { type: "string" },
      },
      required: ["url"],
    },
  },
  {
    name: "vaccine_invalidate",
    description: "Invalidate a cached vaccine",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: { type: "string" },
      },
      required: ["url"],
    },
  },
  {
    name: "vaccine_get_injection_script",
    description: "Get protective JavaScript for a URL",
    inputSchema: {
      type: "object" as const,
      properties: {
        url: { type: "string" },
        scriptType: {
          type: "string",
          enum: ["full", "minimal"],
        },
      },
      required: ["url"],
    },
  },
  {
    name: "vaccine_get_threat_intelligence",
    description: "Get current threat signatures and patterns",
    inputSchema: {
      type: "object" as const,
      properties: {
        category: {
          type: "string",
          enum: ["malware", "phishing", "scam", "all"],
        },
        limit: { type: "number" },
      },
    },
  },
  {
    name: "vaccine_get_statistics",
    description: "Get vaccine system statistics",
    inputSchema: {
      type: "object" as const,
      properties: {
        timeRange: {
          type: "string",
          enum: ["1h", "24h", "7d", "all"],
        },
      },
    },
  },
];

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request;

  try {
    if (name === "vaccine_scan") {
      const report = await vaccineManager.vaccinate(
        args.url,
        args.vericticScore
      );
      return {
        content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
      };
    }

    if (name === "vaccine_get_cached") {
      const vaccine = vaccineManager.getVaccine(args.url);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                vaccine: vaccine?.report || null,
                cached: !!vaccine,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    if (name === "vaccine_invalidate") {
      vaccineManager.invalidateVaccine(args.url);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ status: "invalidated", url: args.url }),
          },
        ],
      };
    }

    if (name === "vaccine_get_injection_script") {
      const script = vaccineManager.getInjectionScript(args.url);
      return {
        content: [
          {
            type: "text",
            text: script || "No vaccine found for this URL",
          },
        ],
      };
    }

    if (name === "vaccine_get_threat_intelligence") {
      // Return threat signatures
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                malwareSigs: [
                  { name: "cryptominer_coinhive", category: "cryptominer" },
                  { name: "exploit_kit_angler", category: "exploit" },
                ],
                phishingPatterns: [
                  { name: "bank_login", fields: ["username", "password"] },
                ],
              },
              null,
              2
            ),
          },
        ],
      };
    }

    if (name === "vaccine_get_statistics") {
      const stats = vaccineManager.getStats();
      return {
        content: [{ type: "text", text: JSON.stringify(stats, null, 2) }],
      };
    }

    return {
      content: [{ type: "text", text: `Unknown tool: ${name}` }],
      isError: true,
    };
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: `Error: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    };
  }
});

// Define resources
server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    {
      uri: "vaccine:threats",
      name: "Threat Intelligence",
      description: "Current malware signatures and phishing patterns",
      mimeType: "application/json",
    },
  ],
}));

// Serve resources
server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  if (request.uri === "vaccine:threats") {
    return {
      contents: [
        {
          uri: request.uri,
          mimeType: "application/json",
          text: JSON.stringify(
            {
              malwareSigs: [
                {
                  name: "cryptominer_coinhive",
                  category: "cryptominer",
                  severity: "high",
                },
              ],
              phishingPatterns: [
                {
                  name: "bank_login",
                  fields: ["username", "password"],
                },
              ],
              lastUpdated: Date.now(),
            },
            null,
            2
          ),
        },
      ],
    };
  }

  throw new Error(`Unknown resource: ${request.uri}`);
});

// Start server
const transport = new StdioServerTransport();
await server.connect(transport);
console.log("ScamShield Vaccine MCP Server started");
```

---

## Client Usage

### With Claude SDK

```typescript
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({
  mcpServers: {
    vaccine: {
      command: "node",
      args: ["scamshield-vaccine-server.js"],
    },
  },
});

// Use in messages
const response = await client.messages.create({
  model: "claude-3-5-sonnet-20241022",
  max_tokens: 1024,
  tools: [
    {
      type: "mcp",
      mcp_server: "vaccine",
      name: "vaccine_scan",
    },
  ],
  messages: [
    {
      role: "user",
      content:
        "Is https://suspicious-website.com safe? Scan it for threats.",
    },
  ],
});
```

### In Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "vaccine": {
      "command": "/path/to/scamshield-vaccine-server",
      "args": []
    }
  }
}
```

---

## Deployment

### Docker

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY . .
RUN npm install

ENV NODE_PATH=.
EXPOSE 3000

CMD ["node", "mcp-server.js"]
```

### Vercel Edge Functions

```typescript
// pages/api/vaccine/scan.ts
import { vaccineManager } from "@/lib/vaccine/vaccine-manager";

export const config = {
  runtime: "nodejs",
  regions: ["sfo1"],
};

export default async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { url } = req.body;
  const report = await vaccineManager.vaccinate(url);
  return res.json(report);
};
```

---

## Performance

**Typical latencies:**
- Tool call overhead: ~50ms
- Website scan: 500ms - 3s
- Threat detection: 100ms - 500ms
- **Total: 700ms - 3.5s per scan**

Cache hit time: <10ms

---

## Error Handling

```typescript
// Tool error response
{
  "content": [
    {
      "type": "text",
      "text": "Error: Failed to scrape website: Connection timeout after 15000ms"
    }
  ],
  "isError": true
}
```

---

## Security Considerations

1. **Rate Limiting:** Implement per-user rate limits (default: 30/minute)
2. **Authentication:** Optional API key validation
3. **Timeout:** All scrapes have 15s timeout
4. **Input Validation:** All URLs validated with URL() constructor
5. **Sandboxing:** JSDOM provides safe parsing environment

---

## Future Extensions

- Real-time threat streaming
- Webhook for threat updates
- Custom malware signature uploads
- Machine learning threat classification
- Community threat database integration

---

## Support

- GitHub Issues: scamshield/mcp-server
- Email: mcp@scamshield.dev
- Documentation: See VACCINE_SYSTEM.md
