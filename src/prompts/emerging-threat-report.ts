import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export function registerEmergingThreatReportPrompt(server: McpServer) {
  server.prompt(
    "emerging-threat-report",
    "Generate a report on emerging threats based on recent activity and trending data",
    {
      days: z.string().optional().describe("Number of days to analyze for emerging threats (1, 7, or 30)"),
      focus_area: z.string().optional().describe("Optional focus area (e.g., 'ransomware', 'IoT', 'healthcare')"),
    },
    async (args, extra) => {
      const days = args.days || "7";
      // Validate days is one of the allowed values
      const validDays = ["1", "7", "30"].includes(days) ? days : "7";
      const focusArea = args.focus_area || "all";

      const description = `Emerging threat intelligence report${focusArea !== "all" ? ` for ${focusArea}` : ""} (${validDays} days)`;

      return {
        description,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `
Generate a comprehensive report on emerging threats${focusArea !== "all" ? ` in the ${focusArea} sector` : ""} based on GreyNoise threat intelligence data from the past ${validDays} days.

You'll want to use the following tools to gather data for this report:
1. First, use the get-trending-vulnerabilities tool to identify current trending threats
2. Then, use the analyze-tags-activity tool to get activity data for the most relevant tags
3. Use the gnql-stats tool with appropriate queries to identify statistical patterns
4. For notable CVEs, use the get-cve-details tool to gather more information

Your report should include:
1. Executive Summary
2. Top Emerging Threats
3. New Attack Vectors and Techniques
4. Notable Vulnerability Exploitations
5. Geographical Threat Distribution
6. Industry-Specific Impacts${focusArea !== "all" ? ` (focusing on ${focusArea})` : ""}
7. Prediction of Near-Future Threats
8. Strategic Recommendations
`,
            },
          },
        ],
      };
    },
  );
}
