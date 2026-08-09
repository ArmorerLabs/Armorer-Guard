import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import {
  ArmorerGuardError,
  evaluatePolicy,
  inspect,
  mcpProxyCommand,
  requireSafeToolArgs,
  sanitize,
  versionInfo,
} from "../index.js";

const bin = process.env.ARMORER_GUARD_BIN;
const hasBinary = Boolean(bin && existsSync(bin));

test("mcpProxyCommand builds a wrapped command", () => {
  const proxy = mcpProxyCommand("npx", ["server"], {
    bin: "/tmp/armorer-guard",
    auditLog: "/tmp/audit.jsonl",
  });
  assert.equal(proxy.command, "/tmp/armorer-guard");
  assert.deepEqual(proxy.args, [
    "mcp-proxy",
    "--audit-log",
    "/tmp/audit.jsonl",
    "--",
    "npx",
    "server",
  ]);
});

test("inspect redacts credentials through the Rust binary", { skip: !hasBinary }, () => {
  const verdict = inspect("GH_TOKEN=dummyGithubToken123456789", { bin });
  assert.equal(verdict.suspicious, true);
  assert.match(verdict.sanitized_text, /\[REDACTED_SECRET_VALUE\]/);
  assert.ok(verdict.reasons.includes("detected:credential"));
});

test("sanitize calls the Rust binary", { skip: !hasBinary }, () => {
  const verdict = sanitize("password=hunter22supersecretvalue", { bin });
  assert.match(String(verdict.sanitized_text), /\[REDACTED_SECRET_VALUE\]/);
});

test("requireSafeToolArgs throws with a verdict for dangerous tool calls", { skip: !hasBinary }, () => {
  assert.throws(
    () =>
      requireSafeToolArgs(
        "Bash",
        { command: "rm -rf /" },
        { bin },
      ),
    (error) => {
      assert.ok(error instanceof ArmorerGuardError);
      assert.equal(error.verdict.suspicious, true);
      assert.ok(error.verdict.reasons.includes("policy:dangerous_tool_call"));
      return true;
    },
  );
});

test("versionInfo returns package metadata through the Rust binary", { skip: !hasBinary }, () => {
  const version = versionInfo({ bin });
  assert.equal(version.name, "armorer-guard");
  assert.equal(version.version, "0.4.0");
});

test("evaluatePolicy binds exact identity authority through the Rust binary", { skip: !hasBinary }, () => {
  const policy = {
    schema_version: "armorer-guard-policy-bundle/v1",
    policy_id: "policy/npm-case-read",
    revision: 1,
    default_effect: "deny",
    invariants: {
      deny_cross_tenant: true,
      deny_untrusted_privilege_expansion: true,
      deny_guard_tampering: true,
      require_signed_delegation: true,
    },
    rules: [{
      rule_id: "allow-exact-case-read",
      priority: 10,
      effect: "allow",
      subjects: {
        agent_ids: ["case-agent"],
        identity_ids: ["service/case-agent"],
        tenant_ids: ["tenant/acme"],
      },
      actions: ["case.read"],
      resources: {
        resource_types: ["case"],
        resource_ids: ["*"],
        tenant_ids: ["tenant/acme"],
      },
      conditions: {
        required_capabilities: ["case.read"],
        required_purposes: ["authorized_utility"],
        required_provenance: "verified",
        required_approval_roles: [],
        max_delegation_depth: 1,
        require_resource_tenant_match: true,
      },
      immutable: false,
    }],
    adaptive: {
      mode: "tightening_only",
      review_risk_threshold: 0.6,
      block_risk_threshold: 0.9,
      allowed_automatic_effects: ["deny", "require_approval"],
      authority_expansion: "human_approval_required",
    },
  };
  const request = {
    schema_version: "armorer-guard-authority-request/v1",
    request_id: "request/npm-case-read",
    subject: {
      agent_id: "case-agent",
      identity_id: "service/case-agent",
      tenant_id: "tenant/acme",
    },
    delegation: {
      delegated_by: "operator/case-owner",
      capability_ids: ["case.read"],
      purpose: "authorized_utility",
      depth: 1,
      expires_at: 2_000,
      signature_verified: true,
    },
    action: "case.read",
    resource: {
      resource_type: "case",
      resource_id: "case/123",
      tenant_id: "tenant/acme",
    },
    context: {
      provenance: "verified",
      risk_score: 0.05,
      approval_roles: [],
      observed_at: 1_000,
    },
  };
  const decision = evaluatePolicy(policy, request, { bin });
  assert.equal(decision.effect, "allow");
  assert.equal(decision.authority_expanded, false);
  assert.deepEqual(decision.matched_rule_ids, ["allow-exact-case-read"]);
});
