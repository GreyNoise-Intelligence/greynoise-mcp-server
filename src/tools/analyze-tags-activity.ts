import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { GreyNoiseTag, GreyNoiseTagActivity, ActivitySummaryTag } from "../types/greynoise-response.js";
import { fetchGreyNoise } from "../utils/fetch.js";
import { getCachedTags } from "../utils/tag-cache.js";
import { getApiKey } from "../utils/api-context.js";

export function registerAnalyzeTagsActivityTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  server.tool(
    "analyze-tags-activity",
    "Analyze activity for multiple tags and provide a summary",
    {
      query: z.string().optional().describe("Optional text to search in name, description, etc."),
      category: z.string().optional().describe("Filter by category (e.g., 'activity')"),
      intention: z.string().optional().describe("Filter by intention (e.g., 'malicious', 'benign')"),
      cve: z.string().optional().describe("Filter by associated CVE identifier"),
      days: z
        .enum(["1", "10", "30"])
        .default("30")
        .describe("Number of days of activity to retrieve (must be 1, 10, or 30)"),
    },
    async ({ query, category, intention, cve, days }) => {
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

        // Apply filters
        let filteredTags = tags;

        if (query) {
          const lowerQuery = query.toLowerCase();
          filteredTags = filteredTags.filter(
            (tag: GreyNoiseTag) =>
              tag.name.toLowerCase().includes(lowerQuery) ||
              tag.description.toLowerCase().includes(lowerQuery) ||
              tag.slug.toLowerCase().includes(lowerQuery) ||
              tag.label.toLowerCase().includes(lowerQuery),
          );
        }

        if (category) {
          const lowerCategory = category.toLowerCase();
          filteredTags = filteredTags.filter((tag: GreyNoiseTag) => tag.category.toLowerCase() === lowerCategory);
        }

        if (intention) {
          const lowerIntention = intention.toLowerCase();
          filteredTags = filteredTags.filter((tag: GreyNoiseTag) => tag.intention.toLowerCase() === lowerIntention);
        }

        // No matching tags
        if (filteredTags.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: "No tags match the specified criteria.",
              },
            ],
          };
        }

        // Convert days string to number
        const daysNum = parseInt(days, 10);

        // Set granularity based on days
        const granularity = daysNum === 1 ? "1h" : "24h";

        // Get activity data for each tag
        const activityPromises = filteredTags.map(async (tag: GreyNoiseTag) => {
          try {
            const activity = await fetchGreyNoise<GreyNoiseTagActivity>(
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
              },
              activity,
            };
          } catch (error) {
            console.error(`Error fetching activity for tag ${tag.id}: ${error}`);
            return null;
          }
        });

        const activityResults = await Promise.all(activityPromises);
        const validResults = activityResults.filter((result): result is NonNullable<typeof result> => result !== null);

        // Generate summary
        const summary = {
          analyzed_tags: validResults.length,
          time_period: {
            days: daysNum,
            granularity,
          },
          total_active_ips_by_classification: {
            malicious: 0,
            suspicious: 0,
            benign: 0,
            unknown: 0,
          } as Record<string, number>,
          most_active_tags: [] as ActivitySummaryTag[],
          tags_detail: validResults
            .map((result) => {
              if (!result) return null;
              const { tag, activity } = result;
              const totalIps = activity.aggregations?.total_ips || 0;

              // Update total counts
              if (activity.aggregations?.classification) {
                for (const [classification, count] of Object.entries(activity.aggregations.classification)) {
                  if (count !== undefined) {
                    // Use type assertion to inform TypeScript that the classification keys match
                    (summary.total_active_ips_by_classification as Record<string, number>)[classification] =
                      ((summary.total_active_ips_by_classification as Record<string, number>)[classification] || 0) +
                      count;
                  }
                }
              }

              // Add to most active tags
              if (totalIps > 0) {
                summary.most_active_tags.push({
                  name: tag.name,
                  slug: tag.slug,
                  total_ips: totalIps,
                  classification: Object.fromEntries(
                    Object.entries(activity.aggregations?.classification || {})
                      .filter(([_, value]) => value !== undefined)
                      .map(([key, value]) => [key, value as number]),
                  ),
                });
              }

              return {
                name: tag.name,
                slug: tag.slug,
                total_ips: totalIps,
                classification: Object.fromEntries(
                  Object.entries(activity.aggregations?.classification || {})
                    .filter(([_, value]) => value !== undefined)
                    .map(([key, value]) => [key, value as number]),
                ),
              };
            })
            .filter(Boolean), // Remove nulls
        };

        // Sort most active tags by total IPs
        summary.most_active_tags.sort((a, b) => b.total_ips - a.total_ips);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(summary, null, 2),
            },
          ],
        };
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error analyzing tags: ${error instanceof Error ? error.message : String(error)}`,
            },
          ],
          isError: true,
        };
      }
    },
  );
}