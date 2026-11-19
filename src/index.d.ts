export type Severity = 'pass' | 'warn' | 'info' | 'error';
export interface Diagnostic { severity: Severity; code: string; message: string; action?: string }
export interface PreflightReport {
  schemaVersion: 1;
  url: string;
  summary: { errors: number; warnings: number; passes: number; informational: number };
  checks: Diagnostic[];
}
export function inspectGoogleIdentityPage(input: {
  url: string;
  headers?: Headers | Record<string, string>;
  html?: string;
}): PreflightReport;
export function scanGoogleIdentityUrl(url: string, options?: {
  fetcher?: typeof fetch;
  timeoutMs?: number;
}): Promise<PreflightReport>;
