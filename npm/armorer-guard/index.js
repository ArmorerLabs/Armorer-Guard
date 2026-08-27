import crypto from "node:crypto";
import net from "node:net";
import tls from "node:tls";

const DEFAULT_TIMEOUT_MS = 2_000;
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const ADMITTED_CONTENT_EFFECTS = new Set([
  "allow",
  "allow_trusted_instruction",
  "allow_untrusted_data",
  "warn_and_allow",
  "redact_and_allow",
]);

export class ArmorerGuardError extends Error {
  constructor(message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = "ArmorerGuardError";
    this.code = options.code;
    this.decision = options.decision;
  }
}

export class GuardApprovalRequiredError extends ArmorerGuardError {
  constructor(decision) {
    super("Armorer Guard requires approval", {
      code: "APPROVAL_REQUIRED",
      decision,
    });
    this.name = "GuardApprovalRequiredError";
  }
}

export class GuardDeniedError extends ArmorerGuardError {
  constructor(decision) {
    super("Armorer Guard denied the operation", {
      code: "GUARD_DENIED",
      decision,
    });
    this.name = "GuardDeniedError";
  }
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive integer`);
  }
  return value;
}

function requestPath(value) {
  if (typeof value !== "string" || !/^\/v1\/[A-Za-z0-9._~/-]+$/.test(value)) {
    throw new TypeError("Guard request path must be a versioned API path");
  }
  return value;
}

export class GuardSidecarClient {
  constructor(options = {}) {
    this.socketPath = options.socketPath
      ?? process.env.ARMORER_GUARD_SOCKET;
    this.timeoutMs = positiveInteger(
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      "timeoutMs",
    );
    this.maxBodyBytes = positiveInteger(
      options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES,
      "maxBodyBytes",
    );
    this.mtls = options.mtls;
    if (this.mtls) {
      const complete = this.mtls.host
        && Number.isSafeInteger(this.mtls.port)
        && this.mtls.port > 0
        && this.mtls.ca
        && this.mtls.cert
        && this.mtls.key;
      if (!complete) {
        throw new TypeError(
          "mTLS requires host, port, CA, client certificate, and private key",
        );
      }
    } else if (typeof this.socketPath !== "string" || !this.socketPath) {
      throw new TypeError(
        "socketPath or ARMORER_GUARD_SOCKET is required when mTLS is not configured",
      );
    }
  }

  request(path, payload, method = "POST") {
    const normalizedPath = requestPath(path);
    if (method !== "GET" && method !== "POST") {
      throw new TypeError("Guard client supports only GET and POST");
    }
    let body;
    try {
      body = payload === undefined ? "" : JSON.stringify(payload);
    } catch (error) {
      throw new ArmorerGuardError("Guard request is not JSON serializable", {
        code: "INVALID_REQUEST",
        cause: error,
      });
    }
    if (Buffer.byteLength(body) > this.maxBodyBytes) {
      throw new ArmorerGuardError("Guard request exceeds the configured size limit", {
        code: "REQUEST_TOO_LARGE",
      });
    }
    const wire = [
      `${method} ${normalizedPath} HTTP/1.1`,
      "Host: armorer-guard.local",
      "Content-Type: application/json",
      `Content-Length: ${Buffer.byteLength(body)}`,
      "Connection: close",
      "",
      body,
    ].join("\r\n");

    return new Promise((resolve, reject) => {
      let settled = false;
      let response = Buffer.alloc(0);
      const succeed = (value) => {
        if (!settled) {
          settled = true;
          resolve(value);
        }
      };
      const fail = (error) => {
        if (!settled) {
          settled = true;
          reject(error instanceof ArmorerGuardError
            ? error
            : new ArmorerGuardError(`Armorer Guard unavailable: ${error.message}`, {
              code: "SIDECAR_UNAVAILABLE",
              cause: error,
            }));
        }
      };
      const socket = this.mtls
        ? tls.connect({
          host: this.mtls.host,
          port: this.mtls.port,
          ca: this.mtls.ca,
          cert: this.mtls.cert,
          key: this.mtls.key,
          servername: this.mtls.servername ?? this.mtls.host,
          rejectUnauthorized: true,
        })
        : net.createConnection({ path: this.socketPath });
      const readyEvent = this.mtls ? "secureConnect" : "connect";
      socket.setTimeout(this.timeoutMs);
      socket.once(readyEvent, () => socket.write(wire));
      socket.on("data", (chunk) => {
        response = Buffer.concat([response, chunk]);
        if (response.length > this.maxBodyBytes + 64 * 1024) {
          socket.destroy(new ArmorerGuardError(
            "Guard response exceeds the configured size limit",
            { code: "RESPONSE_TOO_LARGE" },
          ));
        }
      });
      socket.once("timeout", () => socket.destroy(new ArmorerGuardError(
        "Armorer Guard timed out",
        { code: "SIDECAR_TIMEOUT" },
      )));
      socket.once("error", fail);
      socket.once("end", () => {
        if (settled) return;
        const split = response.indexOf("\r\n\r\n");
        if (split < 0) {
          fail(new ArmorerGuardError("Guard returned an invalid HTTP response", {
            code: "INVALID_RESPONSE",
          }));
          return;
        }
        const header = response.subarray(0, split).toString("utf8");
        const statusMatch = /^HTTP\/1\.[01] (\d{3})(?:\s|$)/.exec(header);
        if (!statusMatch) {
          fail(new ArmorerGuardError("Guard returned an invalid HTTP status", {
            code: "INVALID_RESPONSE",
          }));
          return;
        }
        const status = Number(statusMatch[1]);
        let value;
        try {
          value = JSON.parse(response.subarray(split + 4).toString("utf8") || "{}");
        } catch (error) {
          fail(new ArmorerGuardError("Guard returned invalid JSON", {
            code: "INVALID_RESPONSE",
            cause: error,
          }));
          return;
        }
        if (status < 200 || status >= 300) {
          fail(new ArmorerGuardError(
            value?.error || `Guard returned HTTP ${status}`,
            {
              code: value?.reason_code || status,
              decision: value,
            },
          ));
          return;
        }
        succeed(value);
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
}

export function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("canonical JSON rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
    return `{${entries.join(",")}}`;
  }
  throw new TypeError("canonical JSON accepts only JSON values");
}

export function canonicalDigest(value) {
  return `sha256:${crypto.createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

export function signCanonical(key, value) {
  return `hmac-sha256:${crypto.createHmac("sha256", key).update(canonicalJson(value)).digest("hex")}`;
}

export function protectCapability(client, options) {
  if (!client || typeof options?.authorityRequest !== "function"
      || typeof options?.execute !== "function") {
    throw new TypeError("client, authorityRequest, and execute are required");
  }
  return async function guardedCapability(input, run) {
    const authorityRequest = await options.authorityRequest(input, run);
    const decision = await client.action(authorityRequest);
    if (decision.effect === "require_approval") throw new GuardApprovalRequiredError(decision);
    if (decision.effect !== "allow" || !decision.execution_token) {
      throw new GuardDeniedError(decision);
    }
    const token = decision.execution_token;
    const dispatch = await client.authorizeExecution({
      schema_version: "armorer-guard-execution-dispatch/v1",
      token,
      observed_at: Math.floor(Date.now() / 1000),
    });
    if (dispatch?.authorized !== true) {
      throw new ArmorerGuardError("Guard did not authorize the execution token", {
        code: "EXECUTION_NOT_AUTHORIZED",
        decision: dispatch,
      });
    }
    let result;
    try {
      result = await options.execute(input, token, run);
    } catch (executionError) {
      try {
        await client.recordExecution({
          schema_version: "armorer-guard-execution-report/v1",
          token,
          downstream_dispatched: true,
          downstream_outcome: "failed",
          observed_at: Math.floor(Date.now() / 1000),
        });
      } catch (receiptError) {
        throw new ArmorerGuardError(
          "Downstream execution failed and its Guard receipt could not be recorded",
          {
            code: "RECEIPT_RECORDING_FAILED",
            decision: { executionError, receiptError },
            cause: executionError,
          },
        );
      }
      throw executionError;
    }
    const receipt = await client.recordExecution({
      schema_version: "armorer-guard-execution-report/v1",
      token,
      downstream_dispatched: true,
      downstream_outcome: "succeeded",
      observed_at: Math.floor(Date.now() / 1000),
    });
    if (typeof receipt?.receipt_id !== "string" || !receipt.receipt_id) {
      throw new ArmorerGuardError("Guard did not return an execution receipt", {
        code: "RECEIPT_MISSING",
        decision: receipt,
      });
    }
    return { result, executionReceipt: receipt };
  };
}

function requireExactContentAdmission(decision, envelope, boundary) {
  if (!ADMITTED_CONTENT_EFFECTS.has(decision?.effect)) {
    throw new GuardDeniedError(decision);
  }
  if (!Array.isArray(envelope?.segments) || !Array.isArray(decision?.segments)) {
    throw new ArmorerGuardError(
      `Guard returned an invalid ${boundary} content decision`,
      { code: "INVALID_CONTENT_DECISION", decision },
    );
  }
  const originals = new Map(
    envelope.segments.map((segment) => [segment.content_ref, segment.text]),
  );
  const decidedRefs = new Set(
    decision.segments.map((segment) => segment?.content_ref),
  );
  if (originals.size !== envelope.segments.length
      || decision.segments.length !== originals.size
      || decidedRefs.size !== originals.size
      || decision.segments.some((segment) =>
        !originals.has(segment.content_ref)
        || originals.get(segment.content_ref) !== segment.sanitized_text)) {
    throw new ArmorerGuardError(
      `Guard transformed ${boundary} content that this generic adapter cannot safely reconstruct`,
      { code: "CONTENT_TRANSFORM_UNSUPPORTED", decision },
    );
  }
}

function requireContentAdmission(decision) {
  if (!ADMITTED_CONTENT_EFFECTS.has(decision?.effect)) {
    throw new GuardDeniedError(decision);
  }
  return decision;
}

export async function superviseModelCall(client, options) {
  const requestDecision = await client.modelRequest(options.requestEnvelope);
  requireExactContentAdmission(
    requestDecision,
    options.requestEnvelope,
    "model request",
  );
  const response = await options.invoke(requestDecision);
  const responseEnvelope = await options.responseEnvelope(response, requestDecision);
  const responseDecision = await client.modelResponse(responseEnvelope);
  requireExactContentAdmission(
    responseDecision,
    responseEnvelope,
    "model response",
  );
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
    beforeModel: async (envelope) => {
      const decision = await client.modelRequest(envelope);
      requireExactContentAdmission(decision, envelope, "model request");
      return decision;
    },
    afterModel: async (envelope) => {
      const decision = await client.modelResponse(envelope);
      requireExactContentAdmission(decision, envelope, "model response");
      return decision;
    },
    afterTool: async (envelope) =>
      requireContentAdmission(await client.toolResult(envelope)),
    beforeMemoryWrite: async (envelope) =>
      requireContentAdmission(await client.memoryWrite(envelope)),
    protectTool: (options) => protectCapability(client, options),
  };
}

export function createCrewAIHooks(client) {
  return createLangGraphHooks(client);
}

export function createHttpWebhookGuard(client) {
  return {
    ingress: async (envelope) =>
      requireContentAdmission(await client.input(envelope)),
    egress: async (envelope) =>
      requireContentAdmission(await client.output(envelope)),
  };
}
