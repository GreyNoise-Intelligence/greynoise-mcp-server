# MCP Server For GreyNoise

**REQUIRES AN ENTERPRISE API KEY**

## Installation

### DXT

If you use Claude Desktop or another client that can import MCP servers via DXT files, just download and double-click on the provided DXT.

### For Development
Clone the whole repo and then `npm install && npm run build`.

### For Production/NPX Usage
```bash
npx @greynoise/greynoise-mcp-server --help
```

Note: The bundled version works standalone for stdio transport (default). HTTP transport requires Express to be available.

This is a sample entry for, say, Claude Desktop:

```json
{
  "mcpServers": {
    "greynoise": {
      "command": "npx",
      "args": ["@greynoise/greynoise-mcp-server"],
      "env": {
        "GREYNOISE_API_KEY": "your-greynoise-api-key"
      }
    }
  }
}
```

Or for local development:

```json
{
  "mcpServers": {
    "greynoise": {
      "command": "node",
      "args": ["/absolute/path/to/greynoise-mcp-server/build/index.js"],
      "env": {
        "GREYNOISE_API_KEY": "your-greynoise-api-key"
      }
    }
  }
}
```

## Build System

This project uses `tsup` for modern bundling:

- **`npm run build`**: Creates optimized bundle for distribution
- **`npm run build:dev`**: Development build with source maps
- **`npm run dev`**: Watch mode with auto-rebuild
- **`npm run build:standalone`**: Prepares package for NPX distribution

The bundled output includes all core dependencies except Express (for HTTP transport) and dotenv (due to dynamic require limitations).

## Testing

The project includes a test script for verifying the GreyNoise API endpoints directly:

### Prerequisites

1. Build the project:
   ```bash
   npm run build
   ```

2. Set your GreyNoise Enterprise API key:
   ```bash
   # For Linux/macOS
   export GREYNOISE_API_KEY=your-api-key-here

   # For Windows Command Prompt
   set GREYNOISE_API_KEY=your-api-key-here

   # For Windows PowerShell
   $env:GREYNOISE_API_KEY="your-api-key-here"
   ```

### Running Tests

```bash
# Test all API endpoints
node test-tools.js

# Test a specific API endpoint
node test-tools.js ip-context
node test-tools.js quick-check-ip
node test-tools.js multi-ip-check
node test-tools.js riot-lookup
node test-tools.js tag-list
node test-tools.js tag-details
node test-tools.js tag-activity
node test-tools.js trending-tags
node test-tools.js gnql-stats
node test-tools.js cve-details
```

The test script directly verifies the GreyNoise API endpoints without using the MCP server layer. This helps to:
1. Confirm your API key works correctly
2. Verify connectivity to the GreyNoise API
3. Validate the expected response formats
4. Troubleshoot specific endpoints independently

### Implementation Notes

The test script mimics how the actual MCP tools access the API with some key differences:

- **Tag List & Details**: First retrieves all tags via `v3/tags` and uses client-side filtering for specific tags
- **Tag Activity**: Requires the tag ID (not slug), so it first looks up the tag's details before retrieving activity data
- **Trending Tags**: Combines data from two endpoints: `v3/summary/tags?sort=trending` and `v3/summary/tags?sort=anomalies`
- **Multi-IP Check**: Uses a special POST method rather than the standard GET requests

## MCP Tools and Prompts

This MCP server provides comprehensive access to GreyNoise Intelligence data about internet-scanning IP addresses, threat actors, and vulnerabilities. It includes tools for IP analysis (detailed context, quick checks, batch processing, and business service lookups), tag exploration, vulnerability tracking, and query capabilities.

## Transport Options

### stdio (Default)
The bundled version works completely standalone for stdio transport:
```bash
npx @greynoise/greynoise-mcp-server --transport stdio
```

### http
HTTP transport requires Express to be available in the environment:
```bash
# Ensure Express is available
npm install express
node @greynoise/greynoise-mcp-server --transport http
```

### Available Tools

1. **lookup-ip-context** - Get detailed GreyNoise context information about an IP address

2. **quick-check-ip** - Get a fast, lightweight check of an IP address to determine if it's scanning the internet or is a common business service (uses `v2/noise/quick/{ip}`)

3. **multi-ip-check** - Check multiple IP addresses at once (up to 100) for noise and common business service status (uses `v2/noise/multi/quick` with POST)

4. **riot-lookup** - Check if an IP address belongs to a common business service and get detailed information about the service (uses `v2/riot/{ip}`)

5. **get-tag-list** - Retrieve the complete list of GreyNoise tags with metadata including identifiers, descriptions, categories, and intentions

6. **search-tags** - Search for GreyNoise tags matching a specific query

7. **get-tag-details** - Get comprehensive metadata about a specific GreyNoise tag

8. **get-tag-activity** - Get activity data for a specific GreyNoise tag, including trends over time

9. **analyze-tags-activity** - Analyze activity patterns across multiple tags to identify correlations and trends

10. **get-trending-vulnerabilities** - Get information on vulnerabilities actively being exploited in the wild, as detected by GreyNoise

11. **gnql-stats** - Query GreyNoise's database using the GreyNoise Query Language (GNQL) and retrieve statistical data

12. **get-cve-details** - Get detailed information about a specific CVE, including GreyNoise observations of exploitation attempts

### Usage Examples

#### IP Analysis Tools

```javascript
// Quick check for a single IP
{
  "tool_name": "quick-check-ip",
  "parameters": {
    "ip": "8.8.8.8"
  }
}

// Check multiple IPs at once (up to 100)
{
  "tool_name": "multi-ip-check",
  "parameters": {
    "ips": ["8.8.8.8", "1.1.1.1", "205.251.242.103"]
  }
}

// Look up business service information
{
  "tool_name": "riot-lookup",
  "parameters": {
    "ip": "8.8.8.8"
  }
}

// Get detailed context for an IP
{
  "tool_name": "lookup-ip-context",
  "parameters": {
    "ip": "89.248.165.191"
  }
}

// Get tags and filter for a specific one
{
  "tool_name": "get-tag-details",
  "parameters": {
    "id_or_slug": "scanner"
  }
}

// Get tag activity data (by tag ID or by CVE)
{
  "tool_name": "get-tag-activity",
  "parameters": {
    "id_or_slug": "scanner",
    "days": "30"
  }
}

// Get trending vulnerability tags
{
  "tool_name": "get-trending-vulnerabilities",
  "parameters": {}
}
```

### Available Prompts

1. **vendor-threat-report** - Generate a comprehensive threat report for a vendor technology
   - Produces a detailed analysis including executive summary, threat actor activity, recent vulnerabilities, attack patterns, mitigation recommendations, and confidence assessment
   - Automatically orchestrates multiple GreyNoise data queries to assemble a complete picture of the threat landscape
   - Parameters: vendor (required), technology (optional), timeframe in days 1-90 (required)

2. **ip-threat-analysis** - Generate a detailed analysis of an IP address to determine if it's malicious and associated threats
   - Performs comprehensive threat analysis using GreyNoise data to classify IPs as malicious, benign, or unknown
   - Includes classification, associated tags and activities, geographic/network information, historical activity timeline, threat severity assessment, and recommended actions
   - Parameters: ip (required), include_related true/false (optional)

3. **cve-analysis** - Generate a comprehensive analysis of a CVE including exploitation status and risk assessment
   - Provides detailed vulnerability analysis including current exploitation status, trends, affected systems, attack vectors, geographical distribution, and risk scoring
   - Combines CVE details with real-time exploitation data from GreyNoise observations
   - Parameters: cve_id (required), timeframe in days 1-90 (optional, defaults to 30)

4. **emerging-threat-report** - Generate a report on emerging threats based on recent activity and trending data
   - Identifies and analyzes new and trending threats, attack vectors, vulnerability exploitations, and geographical threat distribution
   - Includes predictions of near-future threats and strategic recommendations
   - Parameters: days (optional: 1, 7, or 30, defaults to 7), focus_area (optional, e.g., 'ransomware', 'IoT', 'healthcare')

5. **security-posture-assessment** - Generate a security posture assessment for an organization based on technologies and vulnerabilities
   - Provides comprehensive security assessment tailored to an organization's technology stack and industry
   - Includes vulnerability analysis for key technologies, exposure assessment, attack surface analysis, risk scoring by component, and prioritized security recommendations
   - Parameters: organization (required), technologies as comma-separated list (required), industry (optional)

6. **threat-hunting** - Generate a threat hunting plan based on specific indicators or patterns
   - Creates detailed hunting plans for different indicator types including IPs, tags, behaviors, actors, or CVEs
   - Provides detection methods, data sources, search patterns, timeline, evidence collection methods, and response procedures
   - Parameters: indicator_type (required: 'ip', 'tag', 'behavior', 'actor', or 'cve'), indicator_value (required), environment description (required)
