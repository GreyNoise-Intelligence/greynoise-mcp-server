import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { IPQuickCheckResponse } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";

export function registerQuickCheckIPTool(server: McpServer, apiBase: string, apiKey: string) {
  server.tool(
    "quick-check-ip",
    "Get a fast, lightweight check of an IP address from GreyNoise",
    {
      ip: z.string().ip().describe("IP address to look up"),
    },
    async ({ ip }) => {
      try {
        // Get quick check information
        const quickCheckData = await fetchGreyNoise<IPQuickCheckResponse>(
          `v2/noise/quick/${ip}`,
          apiBase,
          apiKey,
        );

        // Format response based on noise status
        let statusEmoji = "❓";
        let description = "Unknown status";
        
        if (quickCheckData.noise) {
          statusEmoji = "🔊";
          description = "This IP is classified as NOISE - it has been observed scanning or crawling the internet.";
        } else if (quickCheckData.noise === false) {
          statusEmoji = "🔇";
          description = "This IP is classified as NOT NOISE - it has not been observed scanning or crawling the internet.";
        }

        // Add riot information if available
        let riotInfo = "";
        if (quickCheckData.riot) {
          riotInfo = "\n\n🏢 This IP belongs to a common business service.";
        } else if (quickCheckData.riot === false) {
          riotInfo = "\n\n🏢 This IP does not belong to a common business service.";
        }

        // Construct markdown response
        const summaryText = `
## IP Quick Check: ${ip}

${statusEmoji} **${ip}**: ${description}${riotInfo}

**Code**: ${quickCheckData.code}
`;

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
              text: `Error performing quick IP check: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}