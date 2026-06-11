import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import {
  ArmorerGuardError,
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
  assert.equal(version.version, "0.3.0");
});
