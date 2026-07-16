import { z } from "zod";
import { passthrough } from "../schema-helpers.js";

export const callbackFileSchema = passthrough({
  sha256: z.string().optional(),
  md5: z.string().optional(),
  sha1: z.string().optional(),
  threat_name: z.string().optional(),
  vt_detection_count: z.number().optional(),
  vt_engine_count: z.number().optional(),
  file_name: z.string().optional(),
  size: z.number().optional(),
  type: z.string().optional(),
});

export const callbackFileSummarySchema = passthrough({
  sha256: z.string().optional(),
  file_name: z.string().optional(),
  type: z.string().optional(),
  vt_threat_name: z.string().optional(),
  vt_detection_count: z.number().optional(),
});

export const callbackIPEnrichmentSchema = passthrough({
  asn: z.string().optional(),
  org: z.string().optional(),
  city: z.string().optional(),
  region: z.string().optional(),
  country: z.string().optional(),
  country_code: z.string().optional(),
  latitude: z.number().optional(),
  longitude: z.number().optional(),
  is_tor: z.boolean().optional(),
  route: z.string().optional(),
  type: z.string().optional(),
  domain: z.string().optional(),
  rdns: z.string().optional(),
});

export const callbackIPDetailSchema = passthrough({
  ip: z.string().optional(),
  source_workspaces: z.array(z.string()).optional(),
  attack_stage: z.number().nullable().optional(),
  is_stage_1: z.boolean().optional(),
  is_stage_2: z.boolean().optional(),
  is_riot: z.boolean().optional(),
  riot_trust_level: z.number().optional(),
  first_seen: z.string().nullable().optional(),
  last_seen: z.string().nullable().optional(),
  scanner_ips: z.array(z.string()).optional(),
  scanner_count: z.number().optional(),
  file_count: z.number().optional(),
  active_files: z.array(callbackFileSchema).optional(),
  enrichment: callbackIPEnrichmentSchema.optional(),
});

export const callbackIPSummarySchema = passthrough({
  ip: z.string().optional(),
  source_workspaces: z.array(z.string()).optional(),
  attack_stage: z.number().nullable().optional(),
  is_stage_1: z.boolean().optional(),
  is_stage_2: z.boolean().optional(),
  is_riot: z.boolean().optional(),
  riot_trust_level: z.number().optional(),
  first_seen: z.string().nullable().optional(),
  last_seen: z.string().nullable().optional(),
  scanner_ips: z.array(z.string()).optional(),
  scanner_count: z.number().optional(),
  file_count: z.number().optional(),
  files: z.array(callbackFileSummarySchema).optional(),
  enrichment: callbackIPEnrichmentSchema.optional(),
});

export const callbackListIPsSchema = passthrough({
  items: z.array(callbackIPSummarySchema).optional(),
  total: z.number().optional(),
  page: z.number().optional(),
  page_size: z.number().optional(),
});

export const callbackThreatNameStatSchema = passthrough({
  threat_name: z.string().optional(),
  file_count: z.number().optional(),
  ip_count: z.number().optional(),
});

export const callbackOverviewSchema = passthrough({
  total_ips: z.number().optional(),
  stage_1_ips: z.number().optional(),
  stage_2_ips: z.number().optional(),
  unconfirmed_ips: z.number().optional(),
  total_files: z.number().optional(),
  files_with_vt: z.number().optional(),
  files_without_vt: z.number().optional(),
  total_cross_refs: z.number().optional(),
  total_scanner_links: z.number().optional(),
  ips_with_files: z.number().optional(),
  ips_without_files: z.number().optional(),
  ips_with_scanners: z.number().optional(),
  ips_without_scanners: z.number().optional(),
  distinct_scanners: z.number().optional(),
  riot_level_1_ips: z.number().optional(),
  riot_level_2_ips: z.number().optional(),
  riot_level_3_ips: z.number().optional(),
  not_riot_ips: z.number().optional(),
  top_threat_names: z.array(callbackThreatNameStatSchema).optional(),
});

export const callbackExportSchema = z.string();

export type CallbackIPDetail = z.infer<typeof callbackIPDetailSchema>;
export type CallbackIPSummary = z.infer<typeof callbackIPSummarySchema>;
export type CallbackListIPs = z.infer<typeof callbackListIPsSchema>;
export type CallbackOverview = z.infer<typeof callbackOverviewSchema>;
export type CallbackFile = z.infer<typeof callbackFileSchema>;
