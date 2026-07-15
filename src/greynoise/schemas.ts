import { z } from "zod";
import { passthrough } from "./schema-helpers.js";

export const businessServiceIntelligenceSchema = passthrough({
  found: z.boolean(),
  category: z.string().optional(),
  name: z.string().optional(),
  description: z.string().optional(),
  explanation: z.string().optional(),
  last_updated: z.string().optional(),
  reference: z.string().optional(),
  trust_level: z.string().optional(),
});

export const internetScannerTagSchema = passthrough({
  id: z.string(),
  slug: z.string(),
  name: z.string(),
  category: z.string(),
  intention: z.string(),
  description: z.string(),
  references: z.array(z.string()),
  recommend_block: z.boolean(),
  cves: z.array(z.string()),
  created_at: z.string(),
  updated_at: z.string(),
});

export const internetScannerMetadataSchema = passthrough({
  mobile: z.boolean().optional(),
  source_country: z.string().optional(),
  source_country_code: z.string().optional(),
  source_city: z.string().optional(),
  region: z.string().optional(),
  organization: z.string().optional(),
  rdns: z.string().optional(),
  asn: z.string().optional(),
  category: z.string().optional(),
  os: z.string().optional(),
  destination_countries: z.array(z.string()).optional(),
  destination_country_codes: z.array(z.string()).optional(),
  single_destination: z.boolean().optional(),
  carrier: z.string().optional(),
  datacenter: z.string().optional(),
  domain: z.string().optional(),
  rdns_parent: z.string().optional(),
  rdns_validated: z.boolean().optional(),
  latitude: z.number().optional(),
  longitude: z.number().optional(),
  sensor_count: z.number().optional(),
  sensor_hits: z.number().optional(),
});

export const internetScannerRawDataSchema = passthrough({
  scan: z.array(passthrough({ port: z.number(), protocol: z.string() })).optional(),
  ja3: z.array(passthrough({ fingerprint: z.string(), port: z.number() })).optional(),
  hassh: z.array(passthrough({ fingerprint: z.string(), port: z.number() })).optional(),
  http: passthrough({
    method: z.array(z.string()).optional(),
    path: z.array(z.string()).optional(),
    host: z.array(z.string()).optional(),
    useragent: z.array(z.string()).optional(),
    ja4h: z.array(z.string()).optional(),
  }).optional(),
  tls: passthrough({ cipher: z.string().optional(), ja4: z.array(z.string()).optional() }).optional(),
  ssh: passthrough({ key: z.array(z.string()).optional(), ja4ssh: z.array(z.string()).optional() }).optional(),
  tcp: passthrough({ ja4t: z.array(z.string()).optional(), ja4l: z.string().optional() }).optional(),
  source: passthrough({ bytes: z.number().optional() }).optional(),
});

export const internetScannerIntelligenceSchema = passthrough({
  ip: z.string().optional(),
  seen: z.boolean().optional(),
  classification: z.string().optional(),
  first_seen: z.string().optional(),
  last_seen: z.string().optional(),
  found: z.boolean().optional(),
  actor: z.string().optional(),
  bot: z.boolean().optional(),
  spoofable: z.boolean().optional(),
  cves: z.array(z.string()).optional(),
  tor: z.boolean().optional(),
  vpn: z.boolean().optional(),
  vpn_service: z.string().optional(),
  metadata: internetScannerMetadataSchema.optional(),
  tags: z.array(internetScannerTagSchema).optional(),
  raw_data: internetScannerRawDataSchema.optional(),
});

export const requestMetadataSchema = passthrough({
  restricted_fields: z.array(z.string()).optional(),
  message: z.string().optional(),
});

export const ipContextSchema = passthrough({
  ip: z.string(),
  business_service_intelligence: businessServiceIntelligenceSchema,
  internet_scanner_intelligence: internetScannerIntelligenceSchema,
  request_metadata: requestMetadataSchema.optional(),
});

export const ipQuickCheckSchema = passthrough({
  ip: z.string(),
  business_service_intelligence: passthrough({ found: z.boolean(), trust_level: z.string().optional() }),
  internet_scanner_intelligence: passthrough({ found: z.boolean(), classification: z.string().optional() }),
});

export const multiIpSchema = passthrough({
  data: z.array(ipContextSchema),
  request_metadata: requestMetadataSchema.extend({ ips_not_found: z.array(z.string()).optional() }),
});

export type IPContext = z.infer<typeof ipContextSchema>;
export type IPQuickCheck = z.infer<typeof ipQuickCheckSchema>;
export type MultiIP = z.infer<typeof multiIpSchema>;
