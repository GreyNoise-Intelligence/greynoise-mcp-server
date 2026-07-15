import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { defineTool } from "./define-tool.js";
import { analyzeTagsSummarySchema, tagActivitySchema } from "../greynoise/schemas/tags.js";
import { formatAnalyzeTags, type AnalyzeTagsSummary } from "../utils/formatters/tags.js";
import { getCachedTags } from "../utils/tag-cache.js";
import { logger } from "../utils/logger.js";

export function registerAnalyzeTagsActivityTool(server: McpServer, apiBase: string, apiKeyGetter: () => string) {
  defineTool(server, apiBase, apiKeyGetter, {
    name: "analyze-tags-activity",
    title: "Analyze Tags Activity",
    description:
      "Filter GreyNoise tags then aggregate their v3/tags/{id}/activity into a summary (total active IPs by classification, most active tags, per-tag detail). query substring-matches name/description/slug/label; category and intention are exact (case-insensitive) matches. days must be 1, 10, or 30 (default 30).",
    inputSchema: {
      query: z.string().optional().describe("Substring to match in name, description, slug, or label"),
      category: z.string().optional().describe("Exact category match, e.g. 'activity'"),
      intention: z.string().optional().describe("Exact intention match, e.g. 'malicious', 'benign'"),
      cve: z.string().optional().describe("CVE identifier (accepted for compatibility; not used as a filter)"),
      days: z.enum(["1", "10", "30"]).default("30").describe("Days of activity: 1, 10, or 30"),
    },
    outputSchema: analyzeTagsSummarySchema,
    handler: async ({ query, category, intention, days }, { client }) => {
      let filteredTags = await getCachedTags(client);

      if (query) {
        const q = query.toLowerCase();
        filteredTags = filteredTags.filter(
          (tag) =>
            tag.name.toLowerCase().includes(q) ||
            (tag.description ?? "").toLowerCase().includes(q) ||
            tag.slug.toLowerCase().includes(q) ||
            (tag.label ?? "").toLowerCase().includes(q),
        );
      }
      if (category) {
        const c = category.toLowerCase();
        filteredTags = filteredTags.filter((tag) => (tag.category ?? "").toLowerCase() === c);
      }
      if (intention) {
        const i = intention.toLowerCase();
        filteredTags = filteredTags.filter((tag) => (tag.intention ?? "").toLowerCase() === i);
      }

      if (filteredTags.length === 0) {
        return { text: "No tags match the specified criteria.", structured: { analyzed_tags: 0 } };
      }

      const daysNum = parseInt(days, 10);
      const granularity = daysNum === 1 ? "1h" : "24h";

      const activityResults = await Promise.all(
        filteredTags.map(async (tag) => {
          try {
            const activity = await client.get(`v3/tags/${tag.id}/activity`, tagActivitySchema, {
              days: daysNum,
              granularity,
            });
            return {
              tag: { id: tag.id, name: tag.name, slug: tag.slug, category: tag.category, intention: tag.intention },
              activity,
            };
          } catch (error) {
            logger.warn("Failed to fetch tag activity", {
              tag_id: tag.id,
              error: error instanceof Error ? error.message : String(error),
            });
            return null;
          }
        }),
      );
      const validResults = activityResults.filter((r): r is NonNullable<typeof r> => r !== null);

      const totalActiveIpsByClassification: Record<string, number> = {
        malicious: 0,
        suspicious: 0,
        benign: 0,
        unknown: 0,
      };
      const mostActiveTags: AnalyzeTagsSummary["most_active_tags"] = [];

      const tagsDetail = validResults.map(({ tag, activity }) => {
        const totalIps = activity.aggregations?.total_ips ?? 0;
        const classification = Object.fromEntries(
          Object.entries(activity.aggregations?.classification ?? {}).filter(([, value]) => value !== undefined),
        ) as Record<string, number>;

        for (const [key, count] of Object.entries(classification)) {
          totalActiveIpsByClassification[key] = (totalActiveIpsByClassification[key] ?? 0) + count;
        }

        if (totalIps > 0) {
          mostActiveTags.push({ name: tag.name, slug: tag.slug, total_ips: totalIps, classification });
        }

        return { name: tag.name, slug: tag.slug, total_ips: totalIps, classification };
      });

      mostActiveTags.sort((a, b) => b.total_ips - a.total_ips);

      const summary: AnalyzeTagsSummary = {
        analyzed_tags: validResults.length,
        time_period: { days: daysNum, granularity },
        total_active_ips_by_classification: totalActiveIpsByClassification,
        most_active_tags: mostActiveTags,
        tags_detail: tagsDetail,
      };

      return formatAnalyzeTags(summary);
    },
  });
}
