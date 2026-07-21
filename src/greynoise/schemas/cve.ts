import { z } from "zod";
import { passthrough } from "../schema-helpers.js";

export const cveDetailsSchema = passthrough({
  id: z.string(),
  details: passthrough({
    vulnerability_name: z.string(),
    vulnerability_description: z.string(),
    cve_cvss_score: z.number(),
    product: z.string(),
    vendor: z.string(),
    published_to_nist_nvd: z.boolean(),
  }),
  timeline: passthrough({
    cve_published_date: z.string(),
    cve_last_updated_date: z.string(),
    first_known_published_date: z.string(),
    cisa_kev_date_added: z.string().optional(),
  }),
  exploitation_details: passthrough({
    attack_vector: z.string(),
    exploit_found: z.boolean(),
    exploitation_registered_in_kev: z.boolean(),
    epss_score: z.number(),
  }),
  exploitation_stats: passthrough({
    number_of_available_exploits: z.number(),
    number_of_threat_actors_exploiting_vulnerability: z.number(),
    number_of_botnets_exploiting_vulnerability: z.number(),
  }).nullish(),
  exploitation_activity: passthrough({
    activity_seen: z.boolean(),
    benign_ip_count_1d: z.number(),
    benign_ip_count_10d: z.number(),
    benign_ip_count_30d: z.number(),
    threat_ip_count_1d: z.number(),
    threat_ip_count_10d: z.number(),
    threat_ip_count_30d: z.number(),
  }).nullish(),
});

export const trendingTagSchema = passthrough({
  id: z.string().optional(),
  label: z.string().optional(),
  slug: z.string().optional(),
  name: z.string(),
  category: z.string(),
  intention: z.string(),
  cves: z.array(z.string()).optional(),
  created_at: z.string(),
  total_ips: z.number().optional(),
  score: z.number(),
});

export const trendingTagsResponseSchema = passthrough({
  tags: z.array(trendingTagSchema),
});

export const trendingTagWithSourceSchema = passthrough({
  name: z.string(),
  slug: z.string().optional(),
  category: z.string(),
  intention: z.string(),
  cves: z.array(z.string()).optional(),
  created_at: z.string(),
  score: z.number(),
  source: z.string(),
});

export const trendingTagsSummarySchema = passthrough({
  count: z.number(),
  tags: z.array(trendingTagWithSourceSchema),
});

export type CVEDetails = z.infer<typeof cveDetailsSchema>;
export type TrendingTagsResponse = z.infer<typeof trendingTagsResponseSchema>;
export type TrendingTagsSummary = z.infer<typeof trendingTagsSummarySchema>;
