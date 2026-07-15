import { z } from "zod";

export const passthrough = <T extends z.ZodRawShape>(shape: T) => z.object(shape).passthrough();
