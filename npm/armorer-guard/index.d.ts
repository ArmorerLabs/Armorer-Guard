import type { ChildProcess } from "node:child_process";

export interface GuardContext {
  eval_surface?: string;
  trace_stage?: string;
  policy_scope?: string;
  tool_name?: string;
  destination?: string;
  [key: string]: unknown;
}

export interface GuardOptions {
  bin?: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  context?: GuardContext;
}

export interface ToolCallOptions extends GuardOptions {
  policyScope?: string;
}

export interface GuardVerdict {
  sanitized_text: string;
  suspicious: boolean;
  reasons: string[];
  confidence: number;
  scan_id?: string;
  model_version?: string;
  learning_version?: string;
  [key: string]: unknown;
}

export interface McpProxyOptions extends GuardOptions {
  auditLog?: string;
  stdio?: "inherit" | "pipe" | "ignore";
}

export class ArmorerGuardError extends Error {
  code?: string | number;
  stderr?: string;
  stdout?: string;
  verdict?: GuardVerdict;
}

export function resolveArmorerGuardBin(options?: GuardOptions): string;
export function inspect(text: string, options?: GuardOptions): GuardVerdict;
export function inspectToolCall(
  toolName: string,
  args: unknown,
  options?: ToolCallOptions,
): GuardVerdict;
export function requireSafeToolArgs(
  toolName: string,
  args: unknown,
  options?: ToolCallOptions,
): GuardVerdict;
export function sanitize(text: string, options?: GuardOptions): Record<string, unknown>;
export function detectCredentials(text: string, options?: GuardOptions): Record<string, unknown> | null;
export function capabilities(options?: GuardOptions): Record<string, unknown>;
export function versionInfo(options?: GuardOptions): Record<string, unknown>;
export function mcpProxyCommand(
  serverCommand: string,
  serverArgs?: string[],
  options?: McpProxyOptions,
): { command: string; args: string[] };
export function spawnMcpProxy(
  serverCommand: string,
  serverArgs?: string[],
  options?: McpProxyOptions,
): ChildProcess;
