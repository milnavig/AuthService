export default class APIError extends Error {
  status: number;
  message: string;

  constructor(status: number, message: string) {
    super();
    this.status = status;
    this.message = message;
  }

  static badRequest(message: string) {
    return new APIError(400, message);
  }

  static unauthorized(message: string) {
    return new APIError(401, message);
  }

  static forbidden(message: string) {
    return new APIError(403, message);
  }

  static notFound(message: string) {
    return new APIError(404, message);
  }

  static internal(message: string) {
    return new APIError(500, message);
  }
}