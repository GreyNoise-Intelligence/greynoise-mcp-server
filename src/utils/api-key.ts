/**
 * Gets the GreyNoise API key from environment variables.
 * The env var is set by MCPB manifest config, Claude Desktop config,
 * or the user's shell environment.
 * @returns The GreyNoise API key
 * @throws Error if API key is not provided
 */
export function getGreyNoiseApiKey(): string {
  const apiKey = process.env.GREYNOISE_API_KEY || "";

  if (apiKey === "") {
    throw new Error("GREYNOISE_API_KEY is required. Set it as an environment variable.");
  }

  return apiKey;
}

/**
 * Gets the GreyNoise API base URL
 * @returns The GreyNoise API base URL
 */
export function getGreyNoiseApiBase(): string {
  return process.env.GREYNOISE_API_BASE || "https://api.greynoise.io/";
}