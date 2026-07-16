import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getGreyNoiseApiKey, getGreyNoiseApiBase } from "./utils/api-key.js";
import { logger } from "./utils/logger.js";
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
  registerGnqlStatsTool,
  registerGnqlQueryTool,
  registerGnqlMetadataQueryTool,
  registerGnqlTimeseriesTool,
  registerGnqlTimeseriesStatsTool,
  registerGetCVEDetailsTool,
  registerGetSessionTool,
  registerGetSessionPcapTool,
  registerExportSessionsPcapTool,
} from "./tools/index.js";
import {
  registerVendorThreatReportPrompt,
  registerIPThreatAnalysisPrompt,
  registerCVEAnalysisPrompt,
  registerEmergingThreatReportPrompt,
  registerSecurityPostureAssessmentPrompt,
  registerThreatHuntingPrompt,
} from "./prompts/index.js";
import { registerResources } from "./resources/index.js";
import { registerArticleResources } from "./resources/articles.js";
import { registerBlocklistTools } from "./tools/blocklists.js";
import { registerAlertTools } from "./tools/alerts.js";
import { registerSessionSearchTools } from "./tools/sessions-search.js";
import { registerCallbackTools } from "./tools/callback.js";
import { registerBsiTools } from "./tools/bsi.js";

declare const __PKG_VERSION__: string;

const INSTRUCTIONS = `This MCP server provides comprehensive access to GreyNoise Intelligence data on IP addresses scanning the internet or attempting to exploit vulnerabilities, along with information about GreyNoise's detection capabilities:

- Tags: retrieve comprehensive metadata about detection coverage including tag details, activity, and trending vulnerabilities.
- IP addresses: retrieve comprehensive metadata about IP addresses including Internet Scanner Intelligence (scanning activity, classification, raw scan data) and Business Service Intelligence (BSI - known business services, trust levels). Supports single IP lookup, quick checks, and bulk multi-IP checking.
- CVEs: retrieve information on GreyNoise CVE coverage and internet exploitation activity.
- GNQL: search GreyNoise's database using a powerful domain-specific query language. Full query (with raw scan data) and metadata-only query (lighter, without raw data) are available.
- Recall: temporal analysis of IP activity via timeseries endpoints. Retrieve hourly records or aggregated unique IP counts over time ranges.
- Sessions: access raw network session data captured by GreyNoise sensors. Retrieve session metadata, download PCAP captures for individual sessions, or export PCAPs for multiple sessions matching query criteria.

Each tool provides structured, formatted output for easy analysis and integration.`;

function parseArgs(): { transport: string } {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    process.stdout.write(
      `GreyNoise MCP Server

Usage: gnapi [options]

Options:
  --transport <type>  Transport type to use (default: stdio)
                      Supported types: stdio, http
  --help, -h          Show this help message
`,
    );
    process.exit(0);
  }

  const transportIndex = args.indexOf("--transport");
  const transport = transportIndex !== -1 && args[transportIndex + 1] ? args[transportIndex + 1] : "stdio";
  return { transport };
}

export function createServer(apiBase: string, apiKeyGetter: () => string): McpServer {
  const server = new McpServer(
    { name: "greynoise-mcp", version: __PKG_VERSION__ },
    { capabilities: { tools: {}, prompts: {}, resources: {}, logging: {} }, instructions: INSTRUCTIONS },
  );

  registerGetTagListTool(server, apiBase, apiKeyGetter);
  registerSearchTagsTool(server, apiBase, apiKeyGetter);
  registerGetTagDetailsTool(server, apiBase, apiKeyGetter);
  registerGetTagActivityTool(server, apiBase, apiKeyGetter);
  registerAnalyzeTagsActivityTool(server, apiBase, apiKeyGetter);
  registerGetTrendingVulnerabilitiesTool(server, apiBase, apiKeyGetter);
  registerLookupIPContextTool(server, apiBase, apiKeyGetter);
  registerQuickCheckIPTool(server, apiBase, apiKeyGetter);
  registerMultiIPCheckTool(server, apiBase, apiKeyGetter);
  registerGnqlStatsTool(server, apiBase, apiKeyGetter);
  registerGnqlQueryTool(server, apiBase, apiKeyGetter);
  registerGnqlMetadataQueryTool(server, apiBase, apiKeyGetter);
  registerGnqlTimeseriesTool(server, apiBase, apiKeyGetter);
  registerGnqlTimeseriesStatsTool(server, apiBase, apiKeyGetter);
  registerGetCVEDetailsTool(server, apiBase, apiKeyGetter);
  registerGetSessionTool(server, apiBase, apiKeyGetter);
  registerGetSessionPcapTool(server, apiBase, apiKeyGetter);
  registerExportSessionsPcapTool(server, apiBase, apiKeyGetter);

  registerSessionSearchTools(server, apiBase, apiKeyGetter);
  registerCallbackTools(server, apiBase, apiKeyGetter);
  registerBsiTools(server, apiBase, apiKeyGetter);
  registerBlocklistTools(server, apiBase, apiKeyGetter);
  registerAlertTools(server, apiBase, apiKeyGetter);

  registerResources(server, apiBase, apiKeyGetter);
  registerArticleResources(server, apiBase, apiKeyGetter);

  registerVendorThreatReportPrompt(server);
  registerIPThreatAnalysisPrompt(server);
  registerCVEAnalysisPrompt(server);
  registerEmergingThreatReportPrompt(server);
  registerSecurityPostureAssessmentPrompt(server);
  registerThreatHuntingPrompt(server);

  return server;
}

async function startStdio(apiBase: string): Promise<void> {
  const apiKey = getGreyNoiseApiKey();
  const server = createServer(apiBase, () => apiKey);
  await server.connect(new StdioServerTransport());
  logger.info("GreyNoise MCP Server running", { transport: "stdio" });
}

async function startHttp(apiBase: string): Promise<void> {
  const expressModule = await import("express").catch(() => null);
  if (!expressModule) {
    logger.error("HTTP transport requires express; run 'npm install express' or use --transport stdio");
    process.exit(1);
  }
  const express = expressModule.default;
  const app = express();
  app.use(express.json());

  const port = Number(process.env.PORT ?? 9191);
  const allowedHosts = (process.env.MCP_ALLOWED_HOSTS ?? `127.0.0.1:${port},localhost:${port}`).split(",");

  const methodNotAllowed = (_req: unknown, res: any) =>
    res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null });

  app.post("/mcp", checkAuthorization, async (req: any, res: any) => {
    const server = createServer(apiBase, () => req.greynoiseApiKey);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableDnsRebindingProtection: true,
      allowedHosts,
    });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.error("MCP request failed", { error: error instanceof Error ? error.message : String(error) });
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
      }
    }
  });

  app.get("/mcp", methodNotAllowed);
  app.delete("/mcp", methodNotAllowed);

  app.listen(port, () => logger.info("GreyNoise MCP Server running", { transport: "http", port }));
}

function checkAuthorization(req: any, res: any, next: () => void): void {
  const authHeader = req.headers.authorization;
  const token = authHeader?.startsWith("Bearer ") ? authHeader.substring(7) : "";
  if (!token) {
    res
      .status(401)
      .json({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized: missing Bearer token" }, id: null });
    return;
  }
  req.greynoiseApiKey = token;
  next();
}

async function main(): Promise<void> {
  const { transport } = parseArgs();
  const apiBase = getGreyNoiseApiBase();

  switch (transport) {
    case "stdio":
      await startStdio(apiBase);
      break;
    case "http":
      await startHttp(apiBase);
      break;
    default:
      logger.error("Unsupported transport type", { transport });
      process.exit(1);
  }
}

main().catch((error) => {
  logger.error("Fatal error", { error: error instanceof Error ? error.message : String(error) });
  process.exit(1);
});
