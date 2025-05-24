import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

/**
 * Gets the GreyNoise API key from environment variables
 * @returns The GreyNoise API key
 * @throws Error if API key is not provided
 */
export function getGreyNoiseApiKey(): string {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  
  // Load environment variables from .env file in project root
  dotenv.config({ path: path.resolve(__dirname, "../..", ".env") });
  
  // Also load from default locations (backward compatibility)
  dotenv.config();
  
  const apiKey = process.env.GREYNOISE_API_KEY || "";
  
  // Ensure we have an API key
  if (apiKey === "") {
    throw new Error("GREYNOISE_API_KEY is required. Please add it to your .env file.");
  }
  
  return apiKey;
}

/**
 * Gets the GreyNoise API base URL
 * @returns The GreyNoise API base URL
 */
export function getGreyNoiseApiBase(): string {
  return "https://api.greynoise.io/";
}