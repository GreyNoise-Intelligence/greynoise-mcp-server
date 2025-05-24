import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { MultiIPQuickCheckResponse } from "../types/greynoise-response.js";
import { postToGreyNoise } from "../utils/fetch.js";

export function registerMultiIPCheckTool(server: McpServer, apiBase: string, apiKey: string) {
  server.tool(
    "multi-ip-check",
    "Check multiple IP addresses at once for noise and common business services",
    {
      ips: z.array(z.string().ip()).min(1).max(100).describe("List of IP addresses to check (max 100)"),
    },
    async ({ ips }) => {
      try {
        // Build the request body
        const requestBody = { ips };

        // Get multi IP check information
        const multiCheckData = await postToGreyNoise<MultiIPQuickCheckResponse>(
          `v2/noise/multi/quick`,
          apiBase,
          apiKey,
          requestBody
        );

        // Format the response as a markdown table
        let summaryText = `
## Multi IP Check Results

| IP | Noise | Common Business Service | Code |
|--|--|--|--|
`;

        // Add each IP result to the table
        for (const result of multiCheckData) {
          const noiseStatus = result.noise === true ? "🔊 YES" : result.noise === false ? "🔇 NO" : "❓ Unknown";

          const riotStatus = result.riot === true ? "🏢 YES" : result.riot === false ? "❌ NO" : "❓ Unknown";

          summaryText += `| ${result.ip} | ${noiseStatus} | ${riotStatus} | ${result.code} |\n`;
        }

        // Add summary counts
        const noiseCount = multiCheckData.filter((r) => r.noise === true).length;
        const riotCount = multiCheckData.filter((r) => r.riot === true).length;

        summaryText += `\n**Summary:** ${noiseCount} IPs classified as noise, ${riotCount} IPs identified as common business services.`;

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
              text: `Error performing multi IP check: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
