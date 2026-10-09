import { GreyNoiseApiError } from "../greynoise/errors.js";

export function toUserMessage(error: unknown): string {
  if (error instanceof GreyNoiseApiError) {
    switch (error.status) {
      case 401:
        return "Authentication failed (401): the GreyNoise API key is missing, invalid, or expired. Check the GREYNOISE_API_KEY.";
      case 403:
        return "Not entitled (403): this GreyNoise API key's plan does not include this capability. This is an access limitation, not evidence that the data is absent.";
      case 404:
        return `Not found (404): ${error.endpoint}.`;
      case 429: {
        // A plan's search quota also answers 429, and only the API's message says when it resets.
        const detail = apiMessage(error);
        return detail
          ? `Rate limited (429): the GreyNoise API said: ${detail}`
          : "Rate limited (429): too many requests to the GreyNoise API. Wait a moment and retry.";
      }
      default:
        return `GreyNoise API error (${error.status}): ${error.message}`;
    }
  }
  return `Error: ${error instanceof Error ? error.message : String(error)}`;
}

// apiMessage returns the response body the client kept after the status, or its
// "error" or "message" field when the body is JSON.
function apiMessage(error: GreyNoiseApiError): string {
  const body = error.message.replace(new RegExp(`^${error.status}\\s*`), "").trim();
  if (!body) return "";
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed && typeof parsed === "object") {
      const { error: text, message } = parsed as { error?: unknown; message?: unknown };
      if (typeof text === "string" && text) return text;
      if (typeof message === "string" && message) return message;
    }
  } catch {
    // Not JSON: the body is the message.
  }
  return body;
}
