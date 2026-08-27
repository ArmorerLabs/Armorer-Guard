import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ArmorerGuardError,
  GuardSidecarClient,
  canonicalDigest,
  canonicalJson,
  protectCapability,
  signCanonical,
  superviseModelCall,
} from "../index.js";

test("canonical values are stable", () => {
  const value = { tenant: "tenant/example", args: { ticket: 42 }, allowed: true };
  assert.equal(
    canonicalJson(value),
    '{"allowed":true,"args":{"ticket":42},"tenant":"tenant/example"}',
  );
  assert.match(canonicalDigest(value), /^sha256:[0-9a-f]{64}$/);
  assert.match(signCanonical(Buffer.alloc(32, 7), value), /^hmac-sha256:[0-9a-f]{64}$/);
  assert.throws(() => canonicalJson({ invalid: undefined }), /only JSON values/);
});

test("sidecar methods use only public runtime routes", async () => {
  const client = new GuardSidecarClient({ socketPath: "/tmp/guard-sdk-test.sock" });
  const calls = [];
  client.request = async (path, payload, method = "POST") => {
    calls.push([path, payload, method]);
    return {};
  };
  const marker = { fixture: true };
  await client.input(marker);
  await client.modelRequest(marker);
  await client.modelResponse(marker);
  await client.action(marker);
  await client.toolResult(marker);
  await client.output(marker);
  await client.capabilities();
  await client.operationalStatus();
  await client.authorizeExecution(marker);
  await client.recordExecution(marker);
  assert.deepEqual(calls, [
    ["/v1/input/evaluate", marker, "POST"],
    ["/v1/model/request/evaluate", marker, "POST"],
    ["/v1/model/response/evaluate", marker, "POST"],
    ["/v1/action/evaluate", marker, "POST"],
    ["/v1/tool/result/evaluate", marker, "POST"],
    ["/v1/output/evaluate", marker, "POST"],
    ["/v1/capabilities", undefined, "GET"],
    ["/v1/operations/status", undefined, "GET"],
    ["/v1/executions/authorize", marker, "POST"],
    ["/v1/executions/receipts", marker, "POST"],
  ]);
});

test("protected effects require explicit Guard dispatch authorization", async () => {
  let executed = false;
  const guarded = protectCapability({
    action: async () => ({ effect: "allow", execution_token: { token_id: "token/1" } }),
    authorizeExecution: async () => ({ authorized: false }),
  }, {
    authorityRequest: async () => ({}),
    execute: async () => { executed = true; },
  });
  await assert.rejects(
    guarded({}),
    (error) => error instanceof ArmorerGuardError
      && error.code === "EXECUTION_NOT_AUTHORIZED",
  );
  assert.equal(executed, false);
});

test("protected effects require a recorded receipt", async () => {
  let executed = false;
  const guarded = protectCapability({
    action: async () => ({ effect: "allow", execution_token: { token_id: "token/1" } }),
    authorizeExecution: async () => ({ authorized: true }),
    recordExecution: async () => ({}),
  }, {
    authorityRequest: async () => ({}),
    execute: async () => { executed = true; return "ok"; },
  });
  await assert.rejects(
    guarded({}),
    (error) => error instanceof ArmorerGuardError && error.code === "RECEIPT_MISSING",
  );
  assert.equal(executed, true);
});

test("protected effects return the downstream result with its receipt", async () => {
  const guarded = protectCapability({
    action: async () => ({ effect: "allow", execution_token: { token_id: "token/1" } }),
    authorizeExecution: async () => ({ authorized: true }),
    recordExecution: async () => ({ receipt_id: "receipt/1" }),
  }, {
    authorityRequest: async () => ({}),
    execute: async () => "ok",
  });
  assert.deepEqual(await guarded({}), {
    result: "ok",
    executionReceipt: { receipt_id: "receipt/1" },
  });
});

test("generic model supervision fails closed on transformed content", async () => {
  const envelope = {
    segments: [{ content_ref: "content/sha256:fixture", text: "original" }],
  };
  const client = {
    modelRequest: async () => ({
      effect: "redact_and_allow",
      segments: [{
        content_ref: "content/sha256:fixture",
        sanitized_text: "redacted",
      }],
    }),
  };
  await assert.rejects(
    superviseModelCall(client, {
      requestEnvelope: envelope,
      invoke: async () => "not reached",
      responseEnvelope: async () => envelope,
    }),
    (error) => error instanceof ArmorerGuardError
      && error.code === "CONTENT_TRANSFORM_UNSUPPORTED",
  );
});

test("remote Guard requires a complete mTLS identity", () => {
  assert.throws(
    () => new GuardSidecarClient({ mtls: { host: "guard.internal", port: 8443 } }),
    /mTLS requires/,
  );
});

test("request paths reject header injection", () => {
  const client = new GuardSidecarClient({ socketPath: "/tmp/guard-sdk-test.sock" });
  assert.throws(
    () => client.request("/v1/status\r\nInjected: true", undefined, "GET"),
    /versioned API path/,
  );
});
