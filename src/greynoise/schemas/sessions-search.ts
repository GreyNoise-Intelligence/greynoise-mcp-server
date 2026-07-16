import { z } from "zod";
import { passthrough } from "../schema-helpers.js";

const sessionRecordSchema = passthrough({
  _id: z.string().optional(),
  firstPacket: z.union([z.string(), z.number()]).optional(),
  lastPacket: z.union([z.string(), z.number()]).optional(),
  classification: z.string().optional(),
});

const sessionPaginationSchema = passthrough({
  page: z.number().optional(),
  page_size: z.number().optional(),
  sort_by: z.string().optional(),
  sort_desc: z.boolean().optional(),
});

export const sessionsResponseSchema = passthrough({
  sessions: z.array(sessionRecordSchema).optional(),
  total: z.number().optional(),
  pagination: sessionPaginationSchema.optional(),
  request_metadata: passthrough({}).optional(),
});

const sessionFieldSchema = passthrough({
  value: z.string().optional(),
  label: z.string().optional(),
  description: z.string().optional(),
  type: z.string().optional(),
  group: z.string().optional(),
  sortable: z.boolean().optional(),
});

export const sessionFieldsResponseSchema = passthrough({
  fields: z.array(sessionFieldSchema).optional(),
});

type SessionCountItem = { label?: string; count?: number; children?: SessionCountItem[] } & Record<string, unknown>;
const sessionCountItemSchema: z.ZodType<SessionCountItem> = z.lazy(() =>
  passthrough({
    label: z.string().optional(),
    count: z.number().optional(),
    children: z.array(sessionCountItemSchema).optional(),
  }),
);

export const sessionCountsResponseSchema = passthrough({
  items: z.array(sessionCountItemSchema).optional(),
  total: z.number().optional(),
  request_metadata: passthrough({}).optional(),
});

const sessionConnectionNodeSchema = passthrough({
  id: z.string().optional(),
  type: z.string().optional(),
});

const sessionConnectionLinkSchema = passthrough({
  source: z.string().optional(),
  target: z.string().optional(),
  value: z.number().optional(),
});

export const sessionConnectionsResponseSchema = passthrough({
  nodes: z.array(sessionConnectionNodeSchema).optional(),
  links: z.array(sessionConnectionLinkSchema).optional(),
  total: z.number().optional(),
  request_metadata: passthrough({}).optional(),
});

const sessionTimeseriesPointSchema = passthrough({
  timestamp: z.string().optional(),
  count: z.number().optional(),
});

const sessionTimeseriesItemSchema = passthrough({
  label: z.string().optional(),
  count: z.number().optional(),
  timeseries: z.array(sessionTimeseriesPointSchema).optional(),
});

export const sessionTimeseriesResponseSchema = passthrough({
  timeseries: z.array(sessionTimeseriesPointSchema).optional(),
  items: z.array(sessionTimeseriesItemSchema).optional(),
  total: z.number().optional(),
  request_metadata: passthrough({}).optional(),
});

const sessionUniqueValueSchema = passthrough({
  value: z.string(),
  count: z.coerce.number().optional(),
});

export const sessionUniqueValuesSchema = passthrough({
  field: z.string(),
  include_counts: z.boolean().optional(),
  total: z.number().optional(),
  values: z.array(z.string()),
  rows: z.array(sessionUniqueValueSchema).optional(),
});

export const sessionExportFileSchema = passthrough({
  available: z.boolean().optional(),
  filePath: z.string().optional(),
  fileSize: z.number().optional(),
  type: z.string().optional(),
});

export type SessionsResponse = z.infer<typeof sessionsResponseSchema>;
export type SessionFieldsResponse = z.infer<typeof sessionFieldsResponseSchema>;
export type SessionCountsResponse = z.infer<typeof sessionCountsResponseSchema>;
export type SessionConnectionsResponse = z.infer<typeof sessionConnectionsResponseSchema>;
export type SessionTimeseriesResponse = z.infer<typeof sessionTimeseriesResponseSchema>;
export type SessionUniqueValues = z.infer<typeof sessionUniqueValuesSchema>;
export type SessionExportFile = z.infer<typeof sessionExportFileSchema>;
