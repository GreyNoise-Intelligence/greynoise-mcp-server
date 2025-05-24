import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { IPContextResponse } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";
import { formatIPContext } from "../utils/formatters.js";

export function registerLookupIPContextTool(server: McpServer, apiBase: string, apiKey: string) {
  server.tool(
    "lookup-ip-context",
    "Get detailed GreyNoise context information about an IP address",
    {
      ip: z.string().ip().describe("IP address to look up"),
    },
    async ({ ip }) => {
      try {
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