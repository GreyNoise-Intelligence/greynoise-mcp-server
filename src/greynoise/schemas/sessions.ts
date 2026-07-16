import { z } from "zod";
import { passthrough } from "../schema-helpers.js";

const sessionEndpointSchema = passthrough({
  ip: z.string().optional(),
  port: z.coerce.number().optional(),
  bytes: z.coerce.number().optional(),
  packets: z.coerce.number().optional(),
});

export const sessionSchema = passthrough({
  _id: z.string().optional(),
  id: z.string().optional(),
  firstPacket: z.union([z.string(), z.number()]).optional(),
  lastPacket: z.union([z.string(), z.number()]).optional(),
  source: sessionEndpointSchema.optional(),
  destination: sessionEndpointSchema.optional(),
  classification: z.string().optional(),
});

export const pcapFileSchema = passthrough({
  available: z.boolean(),
  filePath: z.string().optional(),
  fileSize: z.number().optional(),
});

export type Session = z.infer<typeof sessionSchema>;
export type PcapFile = z.infer<typeof pcapFileSchema>;
