export class GreyNoiseApiError extends Error {
  constructor(
    readonly status: number,
    readonly endpoint: string,
    message: string,
  ) {
    super(message);
    this.name = "GreyNoiseApiError";
  }
}
