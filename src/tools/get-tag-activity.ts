import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  GreyNoiseTag,
  TagActivityResponse,
  GreyNoiseTagActivity,
} from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";
import { getCachedTags } from "../utils/tag-cache.js";

export function registerGetTagActivityTool(server: McpServer, apiBase: string, apiKey: string) {
  server.tool(
    "get-tag-activity",
    "Retrieve time-series that includes unique IP counts and intention activity data for a specific GreyNoise tag or by CVE",
    {
      id_or_slug: z.string().optional().describe("Tag ID or slug to retrieve activity for"),
      cve: z.string().optional().describe("CVE identifier to retrieve activity for"),
      days: z
        .enum(["1", "10", "30"])
        .default("30")
        .describe("Number of days of activity to retrieve (must be 1, 10, or 30)"),
    },
    async ({ id_or_slug, cve, days }) => {
      try {
        if (!id_or_slug && !cve) {
          return {
            content: [
              {
                type: "text",
                text: "Either id_or_slug or cve parameter must be provided.",
              },
            ],
            isError: true,
          };
        }

        // Get all tags from cache or API
        const tags = await getCachedTags(apiBase, apiKey);

        // Find matching tag(s)
        let matchingTags: GreyNoiseTag[] = [];

        if (id_or_slug) {
          const tag = tags.find(
            (t: GreyNoiseTag) => t.id === id_or_slug || t.slug === id_or_slug || t.slug === id_or_slug.toLowerCase(),
          );
          if (tag) matchingTags.push(tag);
        } else if (cve) {
          // Search by CVE
          const lowerCve = cve.toLowerCase();
          matchingTags = tags.filter((tag: GreyNoiseTag) =>
            tag.cves.some((c: string) => c.toLowerCase() === lowerCve || c.toLowerCase().includes(lowerCve)),
          );
        }

        if (matchingTags.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: id_or_slug ? `Tag with ID or slug "${id_or_slug}" not found.` : `No tags found for CVE "${cve}".`,
              },
            ],
            isError: true,
          };
        }

        // Convert days string to number
        const daysNum = parseInt(days, 10);

        // Set granularity based on days
        const granularity = daysNum === 1 ? "1h" : "24h";

        // Get activity data for all matching tags
        const results = await Promise.all(
          matchingTags.map(async (tag) => {
            const activityData = await fetchGreyNoise<TagActivityResponse>(
              `v3/tags/${tag.id}/activity`,
              apiBase,
              apiKey,
              {
                days: daysNum,
                granularity,
              },
            );

            return {
              tag: {
                id: tag.id,
                name: tag.name,
                slug: tag.slug,
                category: tag.category,
                intention: tag.intention,
                cves: tag.cves,
              },
              activity: activityData,
            };
          }),
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(results, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error retrieving tag activity: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}
