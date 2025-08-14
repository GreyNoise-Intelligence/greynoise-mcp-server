import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export function registerSecurityPostureAssessmentPrompt(server: McpServer) {
  server.prompt(
    "security-posture-assessment",
    "Generate a security posture assessment for an organization based on technologies and vulnerabilities",
    {
      organization: z.string().describe("The organization name"),
      technologies: z.string().describe("Comma-separated list of key technologies used by the organization"),
      industry: z.string().optional().describe("The industry sector of the organization"),
    },
    async (args, extra) => {
      const organization = args.organization;
      const technologies = args.technologies.split(',').map(t => t.trim());
      const industry = args.industry || "general";

      const description = `Security posture assessment for ${organization}`;

      return {
        description,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `
Generate a comprehensive security posture assessment for ${organization} in the ${industry} industry, focusing on their key technologies: ${technologies.join(", ")}.

You'll want to use the following tools to gather threat intelligence data:
1. For each technology, use the search-tags tool to find relevant tags
2. Then use the get-trending-vulnerabilities tool to identify trending threats
3. For relevant technologies, use vendor-specific GNQL queries with the gnql-stats tool
4. Look up any notable CVEs with the get-cve-details tool

Your assessment should include:
1. Executive Summary
2. Current Threat Landscape for ${industry} Industry
3. Vulnerability Analysis for Key Technologies:
   ${technologies.map((t) => `- ${t}`).join("\n   ")}
4. Exposure Assessment
5. Attack Surface Analysis
6. Threat Actor Intelligence Relevant to Organization
7. Risk Scoring by Technology Component
8. Prioritized Security Recommendations
9. Strategic Roadmap for Security Improvements
`,
            },
          },
        ],
      };
    },
  );
}
