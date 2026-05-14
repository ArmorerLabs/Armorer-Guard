#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import {
  detectCredentials,
  inspect,
  mcpProxyCommand,
  sanitize,
  versionInfo,
} from "./index.js";

function usage(exitCode = 0) {
  const stream = exitCode === 0 ? process.stdout : process.stderr;
  stream.write(`Usage:
  armorer-guard-node inspect [--context JSON]
  armorer-guard-node sanitize
  armorer-guard-node detect-credentials
  armorer-guard-node version
  armorer-guard-node mcp-proxy [--audit-log PATH] -- <server command...>

Reads scan text from stdin. Requires the armorer-guard Rust binary on PATH or ARMORER_GUARD_BIN.
`);
  process.exit(exitCode);
}

function readStdin() {
  return readFileSync(0, "utf8");
}

function parseContext(args) {
  const index = args.indexOf("--context");
  if (index === -1) {
    return {};
  }
  if (!args[index + 1]) {
    throw new Error("--context requires a JSON value");
  }
  return JSON.parse(args[index + 1]);
}

function printJson(value) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

const [mode, ...args] = process.argv.slice(2);

try {
  if (!mode || mode === "--help" || mode === "-h") {
    usage(0);
  }

  if (mode === "inspect") {
    printJson(inspect(readStdin(), { context: parseContext(args) }));
  } else if (mode === "sanitize") {
    printJson(sanitize(readStdin()));
  } else if (mode === "detect-credentials") {
    printJson(detectCredentials(readStdin()));
  } else if (mode === "version") {
    printJson(versionInfo());
  } else if (mode === "mcp-proxy") {
    const separator = args.indexOf("--");
    if (separator === -1 || !args[separator + 1]) {
      usage(1);
    }
    let auditLog;
    const auditIndex = args.indexOf("--audit-log");
    if (auditIndex !== -1 && auditIndex < separator) {
      auditLog = args[auditIndex + 1];
      if (!auditLog) {
        throw new Error("--audit-log requires a path");
      }
    }
    const [serverCommand, ...serverArgs] = args.slice(separator + 1);
    const proxy = mcpProxyCommand(serverCommand, serverArgs, { auditLog });
    const result = spawnSync(proxy.command, proxy.args, { stdio: "inherit" });
    process.exit(result.status ?? 1);
  } else {
    usage(1);
  }
} catch (error) {
  process.stderr.write(`${error.message || error}\n`);
  process.exit(1);
}
