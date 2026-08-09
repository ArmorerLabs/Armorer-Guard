import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  ArmorerGuardError,
  canonicalDigest,
  canonicalJson,
  protectCapability,
  signCanonical,
  GuardSidecarClient,
} from "../index.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../../fixtures/canonical-contract-vectors.json", import.meta.url)),
).vectors[0];

test("canonical contract vector matches Rust and Python", () => {
  assert.equal(canonicalJson(fixture.value), fixture.canonical_json);
  assert.equal(canonicalDigest(fixture.value), fixture.digest);
  assert.equal(signCanonical(Buffer.alloc(32, 7), fixture.value), fixture.signature);
});

test("protected capability never hides a missing failure receipt", async () => {
  const client = {
    action: async () => ({ effect: "allow", execution_token: { token_id: "token/1" } }),
    authorizeExecution: async () => ({}),
    recordExecution: async () => { throw new ArmorerGuardError("spool unavailable"); },
  };
  const guarded = protectCapability(client, {
    authorityRequest: async () => ({}),
    execute: async () => { throw new Error("downstream failed"); },
  });
  await assert.rejects(
    guarded({}, {}),
    (error) => error instanceof ArmorerGuardError && error.code === "RECEIPT_RECORDING_FAILED",
  );
});

test("sidecar routes match shared adapter conformance fixture", async () => {
  const conformance = JSON.parse(
    readFileSync(new URL("../../../fixtures/adapter-conformance.json", import.meta.url)),
  );
  const client = new GuardSidecarClient();
  const calls = [];
  client.request = async (path, payload, method = "POST") => {
    calls.push([path, payload, method]);
    return {};
  };
  const marker = { fixture: true };
  for (const route of conformance.routes) {
    if (route.method === "GET") await client[route.typescript]();
    else await client[route.typescript](marker);
    assert.deepEqual(calls.shift(), [
      route.path,
      route.method === "GET" ? undefined : marker,
      route.method,
    ]);
  }
});

test("remote sidecar requires complete mTLS identity", () => {
  assert.throws(
    () => new GuardSidecarClient({ mtls: { host: "guard.internal", port: 8443 } }),
    /mTLS requires/,
  );
});
