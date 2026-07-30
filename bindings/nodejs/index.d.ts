// Type definitions for @engyon/enprot

declare namespace enprot {
  export const ENPROT_OK: 0;
  export const ENPROT_ERR_PARSE: 1;
  export const ENPROT_ERR_CRYPTO: 2;
  export const ENPROT_ERR_IO: 3;
  export const ENPROT_ERR_INVALID: 4;

  export type ErrorCode =
    | typeof ENPROT_OK
    | typeof ENPROT_ERR_PARSE
    | typeof ENPROT_ERR_CRYPTO
    | typeof ENPROT_ERR_IO
    | typeof ENPROT_ERR_INVALID;

  export type ErrorCategory = "parse" | "crypto" | "io" | "invalid" | "unknown";

  export class EnprotError extends Error {
    readonly code: ErrorCode;
    readonly category: ErrorCategory;
  }

  export interface ProcessConfig {
    operation: "encrypt" | "decrypt" | "store" | "fetch" | "encrypt-store" | "passthrough" | "verify";
    file: string;
    words?: Record<string, string>;
    cipher?: string;
    casdir?: string;
    policy?: string;
    [key: string]: unknown;
  }

  export interface OpOptions {
    words?: Record<string, string>;
    cipher?: string;
    casdir?: string;
    policy?: string;
  }

  export function version(): string;
  export function process(config: ProcessConfig): void;
  export function encrypt(file: string, opts?: OpOptions): void;
  export function decrypt(file: string, opts?: OpOptions): void;
  export function store(file: string, opts?: OpOptions): void;
  export function fetch(file: string, opts?: OpOptions): void;
}

export = enprot;
