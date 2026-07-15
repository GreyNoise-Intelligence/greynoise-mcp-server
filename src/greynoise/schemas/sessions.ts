import { z } from "zod";
import { passthrough } from "../schema-helpers.js";

export const sessionSchema = passthrough({
  _id: z.string().optional(),
  id: z.string().optional(),
  firstPacket: z.union([z.string(), z.number()]).optional(),
  lastPacket: z.union([z.string(), z.number()]).optional(),
  source: passthrough({}).optional(),
  destination: passthrough({}).optional(),
  classification: z.string().optional(),
});

export const pcapFileSchema = passthrough({
  filePath: z.string(),
  fileSize: z.number(),
});

export type Session = z.infer<typeof sessionSchema>;
export type PcapFile = z.infer<typeof pcapFileSchema>;
