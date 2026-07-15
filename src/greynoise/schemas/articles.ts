import { z } from "zod";
import { passthrough } from "../schema-helpers.js";

export const articleCategorySchema = passthrough({
  id: z.string().optional(),
  label: z.string().optional(),
  value: z.string().optional(),
  color: z.string().optional(),
});

export const articleSchema = passthrough({
  id: z.string().optional(),
  title: z.string().optional(),
  subtitle: z.string().optional(),
  description: z.string().optional(),
  category: articleCategorySchema.optional(),
  author: z.string().optional(),
  s3_url: z.string().optional(),
  thumbnail_url: z.string().optional(),
  created_at: z.string().optional(),
  updated_at: z.string().optional(),
  published_at: z.string().optional(),
  is_published: z.boolean().optional(),
});

export const articleListMetadataSchema = passthrough({
  total_results: z.number().optional(),
  current_page: z.number().optional(),
  count: z.number().optional(),
});

export const listArticlesResponseSchema = passthrough({
  metadata: articleListMetadataSchema.optional(),
  data: z.array(articleSchema).optional(),
});

export const articleCategoriesSchema = z.array(articleCategorySchema);

export type ArticleCategory = z.infer<typeof articleCategorySchema>;
export type Article = z.infer<typeof articleSchema>;
export type ListArticlesResponse = z.infer<typeof listArticlesResponseSchema>;
