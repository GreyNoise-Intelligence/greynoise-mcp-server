import { z } from "zod";
import { passthrough } from "../schema-helpers.js";

export const bsiLookupMatchSchema = passthrough({
  cidr: z.string().optional(),
  name: z.string().optional(),
  category: z.string().optional(),
  trust_level: z.string().optional(),
  precedence: z.number().optional(),
});

export const bsiLookupResponseSchema = passthrough({
  ip: z.string().optional(),
  matches: z.array(bsiLookupMatchSchema).optional(),
});

export const bsiBulkResultSchema = passthrough({
  ip: z.string().optional(),
  matches: z.array(bsiLookupMatchSchema).optional(),
});

export const bsiBulkResponseSchema = passthrough({
  results: z.array(bsiBulkResultSchema).optional(),
});

export const bsiTrustResponseSchema = passthrough({
  date: z.string().optional(),
  source: z.string().optional(),
  stats: passthrough({
    trust_levels: z
      .array(
        passthrough({
          trust_level: z.string().optional(),
          ip_count: z.number().optional(),
          cidr_count: z.number().optional(),
        }),
      )
      .optional(),
  }).optional(),
});

export const bsiCompanyResponseSchema = passthrough({
  date: z.string().optional(),
  source: z.string().optional(),
  stats: passthrough({
    companies: z
      .array(
        passthrough({
          name: z.string().optional(),
          category: z.string().optional(),
          trust_level: z.string().optional(),
          ip_count: z.number().optional(),
          cidr_count: z.number().optional(),
        }),
      )
      .optional(),
  }).optional(),
});

export const bsiCategoryResponseSchema = passthrough({
  date: z.string().optional(),
  source: z.string().optional(),
  stats: passthrough({
    categories: z
      .array(
        passthrough({
          category: z.string().optional(),
          ip_count: z.number().optional(),
          cidr_count: z.number().optional(),
        }),
      )
      .optional(),
  }).optional(),
});

export type BSILookupResponse = z.infer<typeof bsiLookupResponseSchema>;
export type BSIBulkResponse = z.infer<typeof bsiBulkResponseSchema>;
export type BSITrustResponse = z.infer<typeof bsiTrustResponseSchema>;
export type BSICompanyResponse = z.infer<typeof bsiCompanyResponseSchema>;
export type BSICategoryResponse = z.infer<typeof bsiCategoryResponseSchema>;
