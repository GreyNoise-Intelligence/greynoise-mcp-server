import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { GreyNoiseTag } from "../types/greynoise-response.js";
import { getCachedTags } from "../utils/tag-cache.js";
import { getApiKey } from "../utils/api-context.js";

export function registerGetTagListTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "get-tag-list",
    `
Retrieve the complete list of GreyNoise tags. Metadata for each tag includes:

- id: a unique identifier for the tag used in some API calls
- name: the human readablename of the tag
- slug: the slugified tag name used in some other API calls
- description: a brief description of the tag's purpose or meaning
- category: the category or type of the tag
- intention: whether the tag activity is benign, malicious, suspicious,or unknown
- references: an optional array of URL references or sources for the tag
- cves: an optional array of CVE identifiers associated with the tag
- created_at: the timestamp when the tag was created
- related_tags: an optional array of related tags that are similar or related to the current tag
`,
    {},
    async ({}) => {
      try {
        // Get API key from context or fallback function
        const apiKey = (() => {
          try {
            return getApiKey();
          } catch {
            return apiKeyGetter();
          }
        })();
        
        // Get tags from cache or API
        const tags = await getCachedTags(apiBase, apiKey);

        // Format the response
        const result = tags.map((tag: GreyNoiseTag) => ({
          name: tag.name,
          slug: tag.slug,
        }));

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  count: result.length,
                  tags: result,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error searching tags: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
