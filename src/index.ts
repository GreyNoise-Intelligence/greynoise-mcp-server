import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getGreyNoiseApiKey, getGreyNoiseApiBase } from "./utils/api-key.js";

// Import tool registration functions
import {
  registerGetTagListTool,
  registerSearchTagsTool,
  registerGetTagDetailsTool,
  registerGetTagActivityTool,
  registerAnalyzeTagsActivityTool,
  registerGetTrendingVulnerabilitiesTool,
  registerLookupIPContextTool,
  registerQuickCheckIPTool,
  registerMultiIPCheckTool,
  registerRiotLookupTool,
  registerGnqlStatsTool,
  registerGetCVEDetailsTool,
} from "./tools/index.js";

// Import prompt registration functions
import { 
  registerVendorThreatReportPrompt,
  registerIPThreatAnalysisPrompt,
  registerCVEAnalysisPrompt,
  registerEmergingThreatReportPrompt,
  registerSecurityPostureAssessmentPrompt,
  registerThreatHuntingPrompt
} from "./prompts/index.js";

// Get API configuration using utility functions
const GREYNOISE_API_BASE = getGreyNoiseApiBase();
let GREYNOISE_API_KEY: string;

try {
  GREYNOISE_API_KEY = getGreyNoiseApiKey();
} catch (error) {
  console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}

// Create MCP Server
const server = new McpServer({
  name: "greynoise-mcp",
  version: "0.1.0",
  capabilities: {
    tools: {},
    prompts: {},
  },
  instructions: `This MCP server provides comprehensive access to GreyNoise Intelligence data on IP addresses scanning the internet or attempting to exploit vulnerabilities, along with information about GreyNoise's detection capabilities:

- Tags: retrieve comprehensive metadata about detection coverage including tag details, activity, and trending vulnerabilities.
- IP addresses: retrieve comprehensive metadata about IP addresses including activity and intention, quick IP checks, multi-IP checking, and RIOT business service lookups.
- CVEs: similar to tags, retrieve information on GreyNoise CVE coverage and internet activity
- GNQL: enables querying GreyNoise's database using a powerful domain-specific query language to retrieve information about IP addresses, tags, and vulnerabilities.

Each tool provides structured, formatted output for easy analysis and integration.
  `,
});

// Register all tools
registerGetTagListTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
registerSearchTagsTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
registerGetTagDetailsTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
registerGetTagActivityTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
registerAnalyzeTagsActivityTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
registerGetTrendingVulnerabilitiesTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
registerLookupIPContextTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
registerQuickCheckIPTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
registerMultiIPCheckTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
registerRiotLookupTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
registerGnqlStatsTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);
registerGetCVEDetailsTool(server, GREYNOISE_API_BASE, GREYNOISE_API_KEY);

// Register all prompts
registerVendorThreatReportPrompt(server);
registerIPThreatAnalysisPrompt(server);
registerCVEAnalysisPrompt(server);
registerEmergingThreatReportPrompt(server);
registerSecurityPostureAssessmentPrompt(server);
registerThreatHuntingPrompt(server);

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("GreyNoise MCP Server running...");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
