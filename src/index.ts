import express, { Request, Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getGreyNoiseApiKey, getGreyNoiseApiBase } from "./utils/api-key.js";

// Parse CLI arguments
function parseArgs() {
  const args = process.argv.slice(2);

  // Check for help flag
  if (args.includes("--help") || args.includes("-h")) {
    console.log(`
GreyNoise MCP Server

Usage: gnapi [options]

Options:
  --transport <type>  Transport type to use (default: stdio)
                      Supported types: stdio
  --help, -h          Show this help message

Examples:
  gnapi
  gnapi --transport stdio
`);
    process.exit(0);
  }

  const transportIndex = args.indexOf("--transport");
  const transport = transportIndex !== -1 && args[transportIndex + 1] ? args[transportIndex + 1] : "stdio";

  return { transport };
}

const { transport } = parseArgs();

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
  registerThreatHuntingPrompt,
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
  let serverTransport;

  switch (transport) {
    case "stdio":
      serverTransport = new StdioServerTransport();
      await server.connect(serverTransport);
      console.error(`GreyNoise MCP Server running with ${transport} transport...`);
      break;
    case "http":
      const app = express();
      app.use(express.json());

      app.post("/mcp", async (req: Request, res: Response) => {
        try {
          const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
          });
          res.on("close", () => {
            console.log("Request closed");
            transport.close();
            server.close();
          });
          await server.connect(transport);
          await transport.handleRequest(req, res, req.body);
        } catch (error) {
          console.error("Error handling MCP request:", error);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: "2.0",
              error: {
                code: -32603,
                message: "Internal server error",
              },
              id: null,
            });
          }
        }
      });

      app.get("/mcp", async (req: Request, res: Response) => {
        console.log("Received GET MCP request");
        res.status(405).json({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: "Method not allowed.",
          },
          id: null,
        });
      });

      app.delete("/mcp", async (req: Request, res: Response) => {
        console.log("Received DELETE MCP request");
        res.writeHead(405).end(
          JSON.stringify({
            jsonrpc: "2.0",
            error: {
              code: -32000,
              message: "Method not allowed.",
            },
            id: null,
          }),
        );
      });

      const PORT = 9191;
      app.listen(PORT, () => {
        console.log(`MCP Stateless Streamable HTTP Server listening on port ${PORT}`);
      });

      break;
    default:
      console.error(`Unsupported transport type: ${transport}`);
      process.exit(1);
  }
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
