import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import tls from "node:tls";
import crypto from "node:crypto";

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

export class GuardApprovalRequiredError extends ArmorerGuardError {
  constructor(decision) {
    super("Armorer Guard requires approval", { verdict: decision });
    this.name = "GuardApprovalRequiredError";
    this.decision = decision;
  }
}

export class GuardDeniedError extends ArmorerGuardError {
  constructor(decision) {
    super("Armorer Guard denied the operation", { verdict: decision });
    this.name = "GuardDeniedError";
    this.decision = decision;
  }
}

export class GuardSidecarClient {
  constructor(options = {}) {
    this.socketPath = options.socketPath || process.env.ARMORER_GUARD_SOCKET || "/tmp/armorer-guard.sock";
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.mtls = options.mtls;
    if (this.mtls && (!this.mtls.ca || !this.mtls.cert || !this.mtls.key)) {
      throw new TypeError("mTLS requires CA, client certificate, and private key material");
    }
  }

  request(path, payload, method = "POST") {
    return new Promise((resolve, reject) => {
      const body = payload === undefined ? "" : JSON.stringify(payload);
      const request = [
        `${method} ${path} HTTP/1.1`,
        "Host: armorer-guard.local",
        "Content-Type: application/json",
        `Content-Length: ${Buffer.byteLength(body)}`,
        "Connection: close",
        "",
        body,
      ].join("\r\n");
      let response = Buffer.alloc(0);
      const socket = this.mtls
        ? tls.connect({ ...this.mtls, rejectUnauthorized: true })
        : net.createConnection({ path: this.socketPath });
      socket.setTimeout(this.timeoutMs);
      socket.on("connect", () => socket.write(request));
      socket.on("data", (chunk) => { response = Buffer.concat([response, chunk]); });
      socket.on("timeout", () => socket.destroy(new Error("Guard sidecar timed out")));
      socket.on("error", (error) => reject(new ArmorerGuardError(error.message, { code: "SIDECAR_UNAVAILABLE" })));
      socket.on("end", () => {
        const split = response.indexOf("\r\n\r\n");
        if (split < 0) return reject(new ArmorerGuardError("Guard returned an invalid HTTP response"));
        const header = response.subarray(0, split).toString("utf8");
        const status = Number(header.split(" ")[1]);
        let value;
        try {
          value = JSON.parse(response.subarray(split + 4).toString("utf8") || "{}");
        } catch (error) {
          return reject(new ArmorerGuardError(`Guard returned invalid JSON: ${error.message}`));
        }
        if (status < 200 || status >= 300) {
          return reject(new ArmorerGuardError(value.error || `Guard returned HTTP ${status}`, {
            code: value.reason_code || status,
            verdict: value,
          }));
        }
        resolve(value);
      });
    });
  }

  input(request) { return this.request("/v1/input/evaluate", request); }
  context(request) { return this.request("/v1/context/evaluate", request); }
  modelRequest(request) { return this.request("/v1/model/request/evaluate", request); }
  modelResponse(request) { return this.request("/v1/model/response/evaluate", request); }
  action(request) { return this.request("/v1/action/evaluate", request); }
  output(request) { return this.request("/v1/output/evaluate", request); }
  toolResult(request) { return this.request("/v1/tool/result/evaluate", request); }
  memoryWrite(request) { return this.request("/v1/memory/write/evaluate", request); }
  memoryRead(request) { return this.request("/v1/memory/read/evaluate", request); }
  interAgent(request) { return this.request("/v1/inter-agent/evaluate", request); }
  capabilities() { return this.request("/v1/capabilities", undefined, "GET"); }
  features() { return this.request("/v1/features", undefined, "GET"); }
  enforcementCoverage() { return this.request("/v1/enforcement/coverage", undefined, "GET"); }
  operationalStatus() { return this.request("/v1/operations/status", undefined, "GET"); }
  createApprovalChallenge(request) { return this.request("/v1/approvals/challenges", request); }
  consumeApproval(request) { return this.request("/v1/approvals/consume", request); }
  authorizeExecution(request) { return this.request("/v1/executions/authorize", request); }
  recordExecution(request) { return this.request("/v1/executions/receipts", request); }
  accessEvidence(request) { return this.request("/v1/evidence/access", request); }
  brokerHttp(request) { return this.request("/v1/gateway/http", request); }
  brokerFilesystem(request) { return this.request("/v1/gateway/filesystem", request); }
  replayTrace(request) { return this.request("/v1/replay/traces", request); }
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function canonicalDigest(value) {
  return `sha256:${crypto.createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

export function signCanonical(key, value) {
  return `hmac-sha256:${crypto.createHmac("sha256", key).update(canonicalJson(value)).digest("hex")}`;
}

export function protectCapability(client, options) {
  if (!client || typeof options?.authorityRequest !== "function" || typeof options?.execute !== "function") {
    throw new TypeError("client, authorityRequest, and execute are required");
  }
  return async function guardedCapability(input, run) {
    const authorityRequest = await options.authorityRequest(input, run);
    const decision = await client.action(authorityRequest);
    if (decision.effect === "require_approval") throw new GuardApprovalRequiredError(decision);
    if (decision.effect !== "allow" || !decision.execution_token) throw new GuardDeniedError(decision);
    await client.authorizeExecution({
      schema_version: "armorer-guard-execution-dispatch/v1",
      token: decision.execution_token,
      observed_at: Math.floor(Date.now() / 1000),
    });
    let result;
    try {
      result = await options.execute(input, decision.execution_token, run);
    } catch (executionError) {
      try {
        await client.recordExecution({
          schema_version: "armorer-guard-execution-report/v1",
          token: decision.execution_token,
          downstream_dispatched: true,
          downstream_outcome: "failed",
          observed_at: Math.floor(Date.now() / 1000),
        });
      } catch (receiptError) {
        throw new ArmorerGuardError(
          `Downstream execution failed and its Guard receipt could not be recorded: ${receiptError.message}`,
          { code: "RECEIPT_RECORDING_FAILED", executionError, receiptError },
        );
      }
      throw executionError;
    }
    await client.recordExecution({
        schema_version: "armorer-guard-execution-report/v1",
        token: decision.execution_token,
        downstream_dispatched: true,
        downstream_outcome: "succeeded",
        observed_at: Math.floor(Date.now() / 1000),
    });
    return result;
  };
}

export async function superviseModelCall(client, options) {
  const requestDecision = await client.modelRequest(options.requestEnvelope);
  if (["deny", "quarantine", "require_approval"].includes(requestDecision.effect)) {
    throw new GuardDeniedError(requestDecision);
  }
  const response = await options.invoke(requestDecision);
  const responseEnvelope = await options.responseEnvelope(response, requestDecision);
  const responseDecision = await client.modelResponse(responseEnvelope);
  if (["deny", "quarantine", "require_approval"].includes(responseDecision.effect)) {
    throw new GuardDeniedError(responseDecision);
  }
  return { response, guard: { request: requestDecision, response: responseDecision } };
}

export function createOpenAICompatibleMiddleware(client) {
  return (options) => superviseModelCall(client, options);
}

export function createOpenAIAgentsHooks(client) {
  return {
    superviseModelCall: (options) => superviseModelCall(client, options),
    protectTool: (options) => protectCapability(client, options),
  };
}

export function createLangGraphHooks(client) {
  return {
    beforeModel: (envelope) => client.modelRequest(envelope),
    afterModel: (envelope) => client.modelResponse(envelope),
    afterTool: (envelope) => client.toolResult(envelope),
    beforeMemoryWrite: (envelope) => client.memoryWrite(envelope),
    protectTool: (options) => protectCapability(client, options),
  };
}

export function createCrewAIHooks(client) {
  return createLangGraphHooks(client);
}

export function createHttpWebhookGuard(client) {
  return {
    ingress: (envelope) => client.input(envelope),
    egress: (envelope) => client.output(envelope),
  };
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

export function evaluatePolicy(policyBundle, request, options = {}) {
  return runGuardJson(
    "policy-evaluate",
    JSON.stringify({ policy_bundle: policyBundle, request }),
    options,
  );
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
