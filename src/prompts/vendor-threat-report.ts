import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export function registerVendorThreatReportPrompt(server: McpServer) {
  server.prompt(
    "vendor-threat-report",
    "Generate a comprehensive threat report for a vendor technology",
    {
      vendor: z.string().describe("The technology vendor name to analyze (e.g., 'Cisco', 'Microsoft')"),
      technology: z.string().optional().describe("Specific product or technology to focus on (optional)"),
      timeframe: z.string().describe("Number of days to look back for threat data (1-90)"),
    },
    async (args, extra) => {
      const vendor = args.vendor;
      const technology = args.technology;
      const timeframe = parseInt(args.timeframe, 10) || 30;

      // Create a description for the prompt that includes instructions for tool usage
      const description = `Comprehensive threat report for ${vendor}${technology ? ` ${technology}` : ""} based on GreyNoise data`;

      return {
        description,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `
Generate a comprehensive threat report on ${vendor}${technology ? ` ${technology}` : ""} using GreyNoise threat intelligence data from the past ${timeframe} days.

You'll want to use the following tools to gather data for this report:
1. First, use the get-trending-vulnerabilities tool to see the current threat landscape
2. Then, use the search-tags tool with query "${vendor}${technology ? ` ${technology}` : ""}" to find relevant tags
3. Iterate through the resultant tag list and use "gnql-stats" tool with the quary 'tags:"TAG NAME"' for each tag to retrieve data for each tag and use that activity data to help forumlate the report response.

Your report should include:
1. Executive Summary
2. Threat Actor Activity
3. Recent Vulnerabilities
4. Attack Patterns and Techniques
5. Mitigation Recommendations
6. Intelligence Confidence Assessment
`,
            },
          },
        ],
      };
    },
  );
}
