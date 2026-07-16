import fetch from "node-fetch";
import { createWriteStream } from "fs";
import { unlink, stat } from "fs/promises";
import { pipeline } from "stream/promises";
import { createHash } from "crypto";
import { z } from "zod";
import { logger } from "../utils/logger.js";
import { GreyNoiseApiError } from "./errors.js";
export { GreyNoiseApiError } from "./errors.js";

const PACKAGE_NAME = "@greynoise/greynoise-mcp-server";
declare const __PKG_VERSION__: string;
const USER_AGENT = `${PACKAGE_NAME}/${typeof __PKG_VERSION__ !== "undefined" ? __PKG_VERSION__ : "dev"}`;

const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RETRIES = 3;

interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  params?: Record<string, unknown>;
  body?: unknown;
  timeoutMs?: number;
  accept?: string;
}

export class GreyNoiseClient {
  constructor(
    private readonly apiBase: string,
    private readonly apiKeyGetter: () => string,
  ) {}

  /** Stable, non-reversible identity for the current API key — safe to use as a cache key. */
  cacheKey(): string {
    return createHash("sha256").update(`${this.apiBase}\0${this.apiKeyGetter()}`).digest("hex");
  }

  private buildUrl(endpoint: string, params?: Record<string, unknown>): URL {
    const url = new URL(`${this.apiBase.replace(/\/$/, "")}/${endpoint.replace(/^\//, "")}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null) url.searchParams.append(key, String(value));
      }
    }
    return url;
  }

  private headers(accept: string): Record<string, string> {
    return { key: this.apiKeyGetter(), "Content-Type": "application/json", Accept: accept, "User-Agent": USER_AGENT };
  }

  private async fetchRaw(endpoint: string, options: RequestOptions): Promise<string> {
    const { method = "GET", params, body, timeoutMs = DEFAULT_TIMEOUT_MS, accept = "application/json" } = options;
    const url = this.buildUrl(endpoint, params).toString();
    const maxRetries = method === "GET" ? MAX_RETRIES : 0;

    let lastError: unknown;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetch(url, {
          method,
          headers: this.headers(accept),
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: controller.signal,
        });

        if (response.status === 429 || response.status >= 500) {
          lastError = new GreyNoiseApiError(response.status, endpoint, `retryable status ${response.status}`);
          if (attempt < maxRetries) {
            await this.backoff(attempt, response.headers.get("retry-after"));
            continue;
          }
          throw lastError;
        }
        if (!response.ok) {
          const detail = await response.text().catch(() => "");
          throw new GreyNoiseApiError(response.status, endpoint, `${response.status} ${detail}`.trim());
        }
        return await response.text();
      } catch (error) {
        lastError = error;
        if (attempt < maxRetries && this.isRetryable(error)) {
          await this.backoff(attempt, null);
          continue;
        }
        throw error;
      } finally {
        clearTimeout(timer);
      }
    }
    throw lastError ?? new Error(`GreyNoise request failed: ${endpoint}`);
  }

  private async send<T>(endpoint: string, schema: z.ZodType<T>, options: RequestOptions): Promise<T> {
    const raw = await this.fetchRaw(endpoint, options);
    try {
      return schema.parse(raw ? JSON.parse(raw) : {});
    } catch (error) {
      if (error instanceof z.ZodError) {
        logger.error("GreyNoise response failed schema validation", { endpoint, issues: error.issues.length });
      }
      throw error;
    }
  }

  private isRetryable(error: unknown): boolean {
    if (error instanceof GreyNoiseApiError) return error.status === 429 || error.status >= 500;
    return true;
  }

  private async backoff(attempt: number, retryAfter: string | null): Promise<void> {
    const delay = Math.max(this.retryAfterMs(retryAfter), 2 ** attempt * 250);
    await new Promise((resolve) => setTimeout(resolve, delay));
  }

  private retryAfterMs(retryAfter: string | null): number {
    if (!retryAfter) return 0;
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
    const dateMs = Date.parse(retryAfter);
    return Number.isNaN(dateMs) ? 0 : Math.max(0, dateMs - Date.now());
  }

  get<T>(endpoint: string, schema: z.ZodType<T>, params?: Record<string, unknown>, timeoutMs?: number): Promise<T> {
    return this.send(endpoint, schema, { method: "GET", params, timeoutMs });
  }

  post<T>(endpoint: string, schema: z.ZodType<T>, body?: unknown, timeoutMs?: number): Promise<T> {
    return this.send(endpoint, schema, { method: "POST", body, timeoutMs });
  }

  put<T>(endpoint: string, schema: z.ZodType<T>, body: unknown): Promise<T> {
    return this.send(endpoint, schema, { method: "PUT", body });
  }

  patch<T>(endpoint: string, schema: z.ZodType<T>, body: unknown): Promise<T> {
    return this.send(endpoint, schema, { method: "PATCH", body });
  }

  del<T>(endpoint: string, schema: z.ZodType<T>): Promise<T> {
    return this.send(endpoint, schema, { method: "DELETE" });
  }

  getText(endpoint: string, params?: Record<string, unknown>): Promise<string> {
    return this.fetchRaw(endpoint, { method: "GET", params, accept: "text/csv, text/plain, application/json" });
  }

  postText(endpoint: string, body?: unknown): Promise<string> {
    return this.fetchRaw(endpoint, { method: "POST", body, accept: "text/plain, application/json" });
  }

  async getBinary(
    endpoint: string,
    outputPath: string,
    params?: Record<string, unknown>,
    accept = "application/vnd.tcpdump.pcap",
    timeoutMs = DEFAULT_TIMEOUT_MS,
  ): Promise<{ filePath: string; fileSize: number }> {
    const url = this.buildUrl(endpoint, params).toString();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { headers: this.headers(accept), signal: controller.signal });
      if (!response.ok) {
        const detail = await response.text().catch(() => "");
        throw new GreyNoiseApiError(response.status, endpoint, `${response.status} ${detail}`.trim());
      }
      if (!response.body) throw new GreyNoiseApiError(response.status, endpoint, "empty response body");
      const fileStream = createWriteStream(outputPath);
      try {
        await pipeline(response.body, fileStream);
      } catch (writeError) {
        await unlink(outputPath).catch(() => {});
        throw writeError;
      }
      const fileStats = await stat(outputPath);
      return { filePath: outputPath, fileSize: fileStats.size };
    } finally {
      clearTimeout(timer);
    }
  }
}
