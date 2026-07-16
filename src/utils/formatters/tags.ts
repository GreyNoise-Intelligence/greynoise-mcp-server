import type { Tag, TagActivity } from "../../greynoise/schemas/tags.js";

const stringify = (value: unknown): string => JSON.stringify(value, null, 2);

export function formatTagList(tags: Tag[]): { text: string; structured: Record<string, unknown> } {
  const list = tags.map((tag) => ({ name: tag.name, slug: tag.slug }));
  const structured = { count: list.length, tags: list };
  return { text: stringify(structured), structured };
}

export function formatTagSearch(tags: Tag[]): { text: string; structured: Record<string, unknown> } {
  const list = tags.map((tag) => ({
    id: tag.id,
    name: tag.name,
    slug: tag.slug,
    category: tag.category,
    intention: tag.intention,
    description: tag.description,
    recommend_block: tag.recommend_block,
    cves: tag.cves,
    created_at: tag.created_at,
    references: tag.references,
  }));
  const structured = { count: list.length, tags: list };
  return { text: stringify(structured), structured };
}

export function formatTagDetails(tag: Tag): { text: string; structured: Record<string, unknown> } {
  return { text: stringify(tag), structured: tag as Record<string, unknown> };
}

export interface TagActivityEntry {
  tag: { id: string; name: string; slug: string; category?: string; intention?: string; cves?: string[] };
  activity: TagActivity;
}

export function formatTagActivity(results: TagActivityEntry[]): {
  text: string;
  structured: Record<string, unknown>;
} {
  return { text: stringify(results), structured: { results } };
}

export interface AnalyzeTagsSummary {
  analyzed_tags: number;
  time_period: { days: number; granularity: string };
  total_active_ips_by_classification: Record<string, number>;
  most_active_tags: Array<{ name: string; slug: string; total_ips: number; classification: Record<string, number> }>;
  tags_detail: Array<Record<string, unknown>>;
}

export function formatAnalyzeTags(summary: AnalyzeTagsSummary): {
  text: string;
  structured: Record<string, unknown>;
} {
  return { text: stringify(summary), structured: summary as unknown as Record<string, unknown> };
}
