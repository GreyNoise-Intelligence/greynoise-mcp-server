import { z } from "zod";
import { passthrough } from "../schema-helpers.js";

export const gnqlPaginationMetadataSchema = passthrough({
  complete: z.boolean(),
  scroll: z.string().optional(),
  query: z.string(),
  adjusted_query: z.string().optional(),
  restricted_fields: z.array(z.string()).optional(),
  message: z.string().optional(),
});

const gnqlItemMetadataSchema = passthrough({
  organization: z.string().optional(),
  source_country: z.string().optional(),
});

const gnqlItemScannerSchema = passthrough({
  classification: z.string().optional(),
  actor: z.string().optional(),
  tags: z.array(passthrough({ name: z.string(), intention: z.string() })).optional(),
  metadata: gnqlItemMetadataSchema.optional(),
  raw_data: passthrough({
    scan: z.array(passthrough({ port: z.number(), protocol: z.string() })).optional(),
  }).optional(),
});

export const gnqlIpItemSchema = passthrough({
  ip: z.string(),
  internet_scanner_intelligence: gnqlItemScannerSchema.optional(),
  business_service_intelligence: passthrough({
    found: z.boolean().optional(),
    name: z.string().optional(),
    trust_level: z.string().optional(),
  }).optional(),
});

export const gnqlQuerySchema = passthrough({
  data: z.array(gnqlIpItemSchema),
  request_metadata: gnqlPaginationMetadataSchema,
});

const statBucket = <T extends z.ZodRawShape>(shape: T) => z.array(passthrough({ count: z.number(), ...shape }));

export const gnqlStatsSchema = passthrough({
  count: z.number(),
  query: z.string(),
  adjusted_query: z.string().optional(),
  stats: passthrough({
    classifications: statBucket({ classification: z.string() }).optional(),
    spoofable: statBucket({ spoofable: z.boolean() }).optional(),
    organizations: statBucket({ organization: z.string() }).optional(),
    countries: statBucket({ country: z.string() }).optional(),
    source_countries: statBucket({ country: z.string() }).optional(),
    destination_countries: statBucket({ country: z.string() }).optional(),
    tags: statBucket({ tag: z.string(), id: z.string() }).optional(),
    actors: statBucket({ actor: z.string() }).optional(),
    operating_systems: statBucket({ operating_system: z.string() }).nullable().optional(),
    categories: statBucket({ category: z.string() }).optional(),
    asns: statBucket({ asn: z.string() }).optional(),
  }),
});

const gnqlTimeseriesRecordSchema = passthrough({
  ip: z.string(),
  internet_scanner_intelligence: passthrough({
    classification: z.string().optional(),
    tags: z.array(z.string()).optional(),
  }).optional(),
});

export const gnqlTimeseriesSchema = z.record(z.string(), z.array(gnqlTimeseriesRecordSchema));
// Object wrapper for the tool outputSchema — the SDK can't derive a JSON Schema from a top-level z.record.
export const gnqlTimeseriesResultSchema = passthrough({ buckets: gnqlTimeseriesSchema });

export const gnqlTimeseriesStatsSchema = passthrough({
  count: z.number(),
  max: z.number(),
  min: z.number(),
  data: z.array(passthrough({ date: z.string(), count: z.number() })),
});

export type GnqlQuery = z.infer<typeof gnqlQuerySchema>;
export type GnqlStats = z.infer<typeof gnqlStatsSchema>;
export type GnqlTimeseries = z.infer<typeof gnqlTimeseriesSchema>;
export type GnqlTimeseriesStats = z.infer<typeof gnqlTimeseriesStatsSchema>;
