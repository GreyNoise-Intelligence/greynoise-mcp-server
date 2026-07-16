import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import { GreyNoiseClient } from "../greynoise/client.js";
import { toUserMessage } from "./tool-errors.js";

export interface ToolContext {
  client: GreyNoiseClient;
  log: (level: "debug" | "info" | "warning" | "error", message: string) => Promise<void>;
}

export interface ToolResult {
  text: string;
  structured?: Record<string, unknown>;
}

export interface ToolConfig<In extends z.ZodRawShape> {
  name: string;
  title: string;
  description: string;
  inputSchema: In;
  outputSchema?: z.ZodTypeAny;
  annotations?: ToolAnnotations;
  handler: (args: z.infer<z.ZodObject<In>>, ctx: ToolContext) => Promise<ToolResult>;
}

export function defineTool<In extends z.ZodRawShape>(
  server: McpServer,
  apiBase: string,
  apiKeyGetter: () => string,
  config: ToolConfig<In>,
): void {
  const client = new GreyNoiseClient(apiBase, apiKeyGetter);
  const callback = async (
    args: z.infer<z.ZodObject<In>>,
    extra?: { sendNotification?: (n: unknown) => Promise<void> },
  ): Promise<CallToolResult> => {
    const log: ToolContext["log"] = async (level, message) => {
      await extra?.sendNotification?.({ method: "notifications/message", params: { level, data: message } });
    };
    try {
      const { text, structured } = await config.handler(args, { client, log });
      return {
        content: [{ type: "text", text }],
        ...(structured !== undefined ? { structuredContent: structured } : {}),
      };
    } catch (error) {
      return { content: [{ type: "text", text: toUserMessage(error) }], isError: true };
    }
  };
  server.registerTool(
    config.name,
    {
      title: config.title,
      description: config.description,
      inputSchema: config.inputSchema,
      ...(config.outputSchema ? { outputSchema: config.outputSchema } : {}),
      annotations: { readOnlyHint: true, openWorldHint: true, ...config.annotations },
    },
    callback as Parameters<typeof server.registerTool>[2],
  );
}
