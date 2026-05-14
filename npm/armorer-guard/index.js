import { spawn, spawnSync } from "node:child_process";

const DEFAULT_TIMEOUT_MS = 2000;

export class ArmorerGuardError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "ArmorerGuardError";
    this.code = options.code;
    this.stderr = options.stderr;
    this.stdout = options.stdout;
    this.verdict = options.verdict;
  }
}

export function resolveArmorerGuardBin(options = {}) {
  return options.bin || process.env.ARMORER_GUARD_BIN || "armorer-guard";
}

function runGuard(mode, input, options = {}) {
  const result = spawnSync(resolveArmorerGuardBin(options), [mode], {
    input,
    encoding: "utf8",
    timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    env: options.env ? { ...process.env, ...options.env } : process.env,
  });

  if (result.error) {
    throw new ArmorerGuardError(result.error.message, {
      code: result.error.code,
      stderr: result.stderr,
      stdout: result.stdout,
    });
  }

  if (result.status !== 0) {
    throw new ArmorerGuardError(
      (result.stderr || result.stdout || "Armorer Guard failed").trim(),
      {
        code: result.status,
        stderr: result.stderr,
        stdout: result.stdout,
      },
    );
  }

  return result.stdout;
}

function runGuardJson(mode, input, options = {}) {
  const stdout = runGuard(mode, input, options);
  try {
    return JSON.parse(stdout || "{}");
  } catch (error) {
    throw new ArmorerGuardError(`Armorer Guard returned invalid JSON: ${error.message}`, {
      stdout,
    });
  }
}

export function inspect(text, options = {}) {
  const payload = JSON.stringify({
    text: String(text ?? ""),
    context: options.context ?? {},
  });
  return runGuardJson("inspect-json", payload, options);
}

export function inspectToolCall(toolName, args, options = {}) {
  return inspect(JSON.stringify(args ?? {}), {
    ...options,
    context: {
      eval_surface: "tool_call_args",
      trace_stage: "action",
      policy_scope: options.policyScope ?? "mcp",
      tool_name: toolName,
      ...(options.context ?? {}),
    },
  });
}

export function requireSafeToolArgs(toolName, args, options = {}) {
  const verdict = inspectToolCall(toolName, args, options);
  if (verdict.suspicious) {
    throw new ArmorerGuardError(`Armorer Guard blocked ${toolName}`, { verdict });
  }
  return verdict;
}

export function sanitize(text, options = {}) {
  return runGuardJson("sanitize", String(text ?? ""), options);
}

export function detectCredentials(text, options = {}) {
  return runGuardJson("detect-credentials", String(text ?? ""), options);
}

export function capabilities(options = {}) {
  return runGuardJson("capabilities", "", options);
}

export function versionInfo(options = {}) {
  return runGuardJson("version", "", options);
}

export function mcpProxyCommand(serverCommand, serverArgs = [], options = {}) {
  if (!serverCommand) {
    throw new TypeError("serverCommand is required");
  }

  const args = ["mcp-proxy"];
  if (options.auditLog) {
    args.push("--audit-log", String(options.auditLog));
  }
  args.push("--", String(serverCommand), ...serverArgs.map(String));
  return {
    command: resolveArmorerGuardBin(options),
    args,
  };
}

export function spawnMcpProxy(serverCommand, serverArgs = [], options = {}) {
  const proxy = mcpProxyCommand(serverCommand, serverArgs, options);
  return spawn(proxy.command, proxy.args, {
    stdio: options.stdio ?? "inherit",
    env: options.env ? { ...process.env, ...options.env } : process.env,
  });
}
