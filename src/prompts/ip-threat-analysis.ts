import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export function registerIPThreatAnalysisPrompt(server: McpServer) {
  server.prompt(
    "ip-threat-analysis",
    "Generate a detailed analysis of an IP address to determine if it's malicious and associated threats",
    {
      ip: z.string().describe("The IP address to analyze"),
      include_related: z
        .string()
        .optional()
        .describe("Whether to include information about related IPs/networks (true/false)"),
    },
    async (args, extra) => {
      const ip = args.ip;
      const includeRelated = args.include_related?.toLowerCase() !== "false";

      const description = `Detailed threat analysis for IP: ${ip}`;

      return {
        description,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `
Perform a comprehensive threat analysis on IP address ${ip} using GreyNoise threat intelligence data.

Use the following tools to gather data for your analysis:
1. First, use the lookup-ip-context tool with the IP address to get detailed context information
2. Then, use the gnql-stats tool with a query like 'ip:${ip}' to get statistical information
3. If ${includeRelated ? "true" : "false"}, run additional gnql-stats queries to find related IPs from the same networks or with similar behavior patterns

Your report should include:
1. Executive Summary
2. Classification (Malicious/Benign/Unknown)
3. Associated Tags and Activities
4. Geographic and Network Information
5. Historical Activity Timeline
6. Related IPs and Networks (if requested)
7. Threat Severity Assessment
8. Recommended Actions
`,
            },
          },
        ],
      };
    },
  );
}
