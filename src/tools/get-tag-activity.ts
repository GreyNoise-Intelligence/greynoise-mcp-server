import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { tagActivityResultSchema, tagActivitySchema, type Tag } from "../greynoise/schemas/tags.js";
import { formatTagActivity, type TagActivityEntry } from "../utils/formatters/tags.js";
import { getCachedTags } from "../utils/tag-cache.js";

export function registerGetTagActivityTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "get-tag-activity",
    title: "Get Tag Activity",
    description:
      "Retrieve time-series unique-IP counts and intention activity for a tag (by id/slug) or by CVE, from v3/tags/{id}/activity. Provide exactly one of id_or_slug or cve. days must be 1, 10, or 30 (default 30); granularity is 1h for 1 day, else 24h.",
    inputSchema: {
      id_or_slug: z.string().optional().describe("Tag ID or slug to retrieve activity for"),
      cve: z.string().optional().describe("CVE identifier to retrieve activity for (matches associated tags)"),
      days: z.enum(["1", "10", "30"]).default("30").describe("Days of activity: 1, 10, or 30"),
    },
    outputSchema: tagActivityResultSchema,
    handler: async ({ id_or_slug, cve, days }, { client }) => {
      if (Boolean(id_or_slug) === Boolean(cve)) {
        throw new Error("Provide exactly one of id_or_slug or cve.");
      }

      const tags = await getCachedTags(client);

      let matchingTags: Tag[] = [];
      if (id_or_slug) {
        const tag = tags.find(
          (t) => t.id === id_or_slug || t.slug === id_or_slug || t.slug === id_or_slug.toLowerCase(),
        );
        if (tag) matchingTags.push(tag);
      } else if (cve) {
        const v = cve.toLowerCase();
        matchingTags = tags.filter((tag) =>
          (tag.cves ?? []).some((c) => c.toLowerCase() === v || c.toLowerCase().includes(v)),
        );
      }

      if (matchingTags.length === 0) {
        throw new Error(id_or_slug ? `Tag with ID or slug "${id_or_slug}" not found.` : `No tags found for CVE "${cve}".`);
      }

      const daysNum = parseInt(days, 10);
      const granularity = daysNum === 1 ? "1h" : "24h";

      const results: TagActivityEntry[] = await Promise.all(
        matchingTags.map(async (tag) => {
          const activity = await client.get(`v3/tags/${tag.id}/activity`, tagActivitySchema, {
            days: daysNum,
            granularity,
          });
          return {
            tag: {
              id: tag.id,
              name: tag.name,
              slug: tag.slug,
              category: tag.category,
              intention: tag.intention,
              cves: tag.cves,
            },
            activity,
          };
        }),
      );

      return formatTagActivity(results);
    },
  });
}
