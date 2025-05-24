import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { IPContextResponse } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";
import { formatIPContext } from "../utils/formatters.js";
import { getApiKey } from "../utils/api-context.js";

export function registerLookupIPContextTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "lookup-ip-context",
    "Get detailed GreyNoise context information about an IP address",
    {
      ip: z.string().ip().describe("IP address to look up"),
    },
    async ({ ip }) => {
      try {
        // Get API key from context or fallback function
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();
        
        // Get IP context information
        const contextData = await fetchGreyNoise<IPContextResponse>(
          `v2/noise/context/${ip}`,
          apiBase,
          apiKey,
        );

        // Format a readable response
        const summaryText = formatIPContext(contextData);

        return {
          content: [
            {
              type: "text",
              text: summaryText,
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error looking up IP context: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}