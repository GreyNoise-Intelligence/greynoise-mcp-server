import { z } from "zod";
import { passthrough } from "../schema-helpers.js";

export const tagSchema = passthrough({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  description: z.string().optional(),
  category: z.string().optional(),
  intention: z.string().optional(),
  label: z.string().optional(),
  recommend_block: z.boolean().optional(),
  cves: z.array(z.string()).optional(),
  created_at: z.string().optional(),
  references: z.array(z.string()).optional(),
});

export const tagsListSchema = passthrough({ tags: z.array(tagSchema) });

export const tagActivitySchema = passthrough({
  slug: z.string().optional(),
  aggregations: passthrough({
    total_ips: z.number().optional(),
    classification: z.record(z.string(), z.number()).optional(),
  }).optional(),
  timeline: z
    .array(passthrough({ bucket: z.string(), metrics: passthrough({ total_ips: z.number() }) }))
    .optional(),
});

export const tagActivityResultSchema = passthrough({
  results: z.array(
    passthrough({
      tag: passthrough({
        id: z.string(),
        name: z.string(),
        slug: z.string(),
        category: z.string().optional(),
        intention: z.string().optional(),
        cves: z.array(z.string()).optional(),
      }),
      activity: tagActivitySchema,
    }),
  ),
});

export const tagListResultSchema = passthrough({
  count: z.number(),
  tags: z.array(passthrough({ name: z.string(), slug: z.string() })),
});

export const tagSearchResultSchema = passthrough({
  count: z.number(),
  tags: z.array(tagSchema),
});

export const analyzeTagsSummarySchema = passthrough({
  analyzed_tags: z.number(),
  time_period: passthrough({ days: z.number(), granularity: z.string() }).optional(),
  total_active_ips_by_classification: z.record(z.string(), z.number()).optional(),
  most_active_tags: z.array(z.unknown()).optional(),
  tags_detail: z.array(z.unknown()).optional(),
  message: z.string().optional(),
});

export type Tag = z.infer<typeof tagSchema>;
export type TagsList = z.infer<typeof tagsListSchema>;
export type TagActivity = z.infer<typeof tagActivitySchema>;
