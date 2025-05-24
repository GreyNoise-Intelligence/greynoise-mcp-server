import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getGreyNoiseApiKey, getGreyNoiseApiBase } from "./utils/api-key.js";
import { runWithApiContext } from "./utils/api-context.js";

// Dynamic Express import function for standalone operation
async function loadExpress() {
  try {
    const expressModule = await import("express");
    return expressModule.default;
  } catch (error) {
    return null;
  }
}

// Parse CLI arguments
function parseArgs() {
  const args = process.argv.slice(2);

  // Check for help flag
  if (args.includes("--help") || args.includes("-h")) {
    console.log(`
GreyNoise MCP Server

Usage: npm run build/index.js [options]

Options:
  --transport <type>  Transport type to use (default: stdio)
                      Supported types: stdio, http
  --help, -h          Show this help message

Examples:
  npm run build/index.js --transport stdio
  npm run build/index.js --transport http
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
let GREYNOISE_API_KEY: string | undefined;

// For stdio transport, we need the API key at startup
if (transport === "stdio") {
  try {
    GREYNOISE_API_KEY = getGreyNoiseApiKey();
  } catch (error) {
    console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}

// Authorization middleware for HTTP transport
function checkAuthorization(req: any, res: any, next: any): void {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({
      jsonrpc: "2.0",
      error: {
        code: -32001,
        message: "Unauthorized: Missing or invalid Authorization header",
      },
      id: null,
    });
    return;
  }

  const token = authHeader.substring(7); // Remove 'Bearer ' prefix

  if (!token) {
    res.status(401).json({
      jsonrpc: "2.0",
      error: {
        code: -32001,
        message: "Unauthorized: Empty token",
      },
      id: null,
    });
    return;
  }

  // Store the API key (Bearer token) in the request for use by tools
  req.greynoiseApiKey = token;

  next();
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

// Function to get API key for stdio transport
function getStaticApiKey(): string {
  if (GREYNOISE_API_KEY) {
    return GREYNOISE_API_KEY;
  }
  throw new Error("No GreyNoise API key available");
}

// Register all tools with API key getter function
registerGetTagListTool(server, GREYNOISE_API_BASE, getStaticApiKey);
registerSearchTagsTool(server, GREYNOISE_API_BASE, getStaticApiKey);
registerGetTagDetailsTool(server, GREYNOISE_API_BASE, getStaticApiKey);
registerGetTagActivityTool(server, GREYNOISE_API_BASE, getStaticApiKey);
registerAnalyzeTagsActivityTool(server, GREYNOISE_API_BASE, getStaticApiKey);
registerGetTrendingVulnerabilitiesTool(server, GREYNOISE_API_BASE, getStaticApiKey);
registerLookupIPContextTool(server, GREYNOISE_API_BASE, getStaticApiKey);
registerQuickCheckIPTool(server, GREYNOISE_API_BASE, getStaticApiKey);
registerMultiIPCheckTool(server, GREYNOISE_API_BASE, getStaticApiKey);
registerRiotLookupTool(server, GREYNOISE_API_BASE, getStaticApiKey);
registerGnqlStatsTool(server, GREYNOISE_API_BASE, getStaticApiKey);
registerGetCVEDetailsTool(server, GREYNOISE_API_BASE, getStaticApiKey);

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
      const express = await loadExpress();
      if (!express) {
        console.error("Error: Express is not available. HTTP transport requires Express to be installed.");
        console.error("Run 'npm install express' or use --transport stdio instead.");
        process.exit(1);
      }
      const app = express();
      app.use(express.json());

      app.post("/mcp", checkAuthorization, async (req: any, res: any) => {
        try {
          const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
            sessionIdGenerator: undefined,
          });
          res.on("close", () => {
            console.log("Request closed");
            transport.close();
            server.close();
          });
          console.log(req);
          // Run the MCP request within the API context using the Bearer token
          await runWithApiContext(req.greynoiseApiKey, async () => {
            await server.connect(transport);
            await transport.handleRequest(req, res, req.body);
          });
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

      app.get("/mcp", async (req: any, res: any) => {
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

      app.delete("/mcp", async (req: any, res: any) => {
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
