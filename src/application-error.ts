export class ApplicationError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApplicationError";
    this.status = status;
    this.code = code;
  }
}
