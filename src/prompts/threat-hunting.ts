import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export function registerThreatHuntingPrompt(server: McpServer) {
  server.prompt(
    "threat-hunting",
    "Generate a threat hunting plan based on specific indicators or patterns",
    {
      indicator_type: z.string().describe("Type of indicator to hunt for (ip, tag, behavior, actor, cve)"),
      indicator_value: z.string().describe("The specific indicator value to hunt for"),
      environment: z.string().describe("Brief description of the environment to hunt within"),
    },
    async (args, extra) => {
      const rawIndicatorType = args.indicator_type.toLowerCase();
      const validTypes = ["ip", "tag", "behavior", "actor", "cve"];
      const indicatorType = validTypes.includes(rawIndicatorType) ? rawIndicatorType : "ip";
      const indicatorValue = args.indicator_value;
      const environment = args.environment;

      const description = `Threat hunting plan for ${indicatorType}: ${indicatorValue}`;

      return {
        description,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `
Generate a comprehensive threat hunting plan for identifying ${indicatorType}-based threats related to ${indicatorValue} within ${environment}.

Use the following tools to gather intelligence for your hunting plan:
${indicatorType === "ip" ? "1. Use the lookup-ip-context tool to get detailed information about the IP" : ""}
${indicatorType === "tag" ? "1. Use the get-tag-details tool to get information about the tag\n2. Use the get-tag-activity tool to analyze recent activity patterns" : ""}
${indicatorType === "behavior" ? "1. Use the search-tags tool to find tags related to this behavior\n2. Use the gnql-stats tool with behavior-related queries" : ""}
${indicatorType === "actor" ? "1. Use the gnql-stats tool with actor-specific queries\n2. Search for tags associated with this actor" : ""}
${indicatorType === "cve" ? "1. Use the get-cve-details tool to get information about the vulnerability\n2. Use the gnql-stats tool with CVE-specific queries" : ""}
3. Use other relevant tools to gather comprehensive intelligence

Your threat hunting plan should include:
1. Executive Summary
2. Threat Actor Profile or Signature
3. Recommended Detection Methods
4. Data Sources to Query
5. Search Patterns and Queries
6. Timeline for Hunting Activities
7. Evidence Collection Methods
8. Escalation and Response Procedures
9. Recommended Tools and Techniques
`,
            },
          },
        ],
      };
    },
  );
}
