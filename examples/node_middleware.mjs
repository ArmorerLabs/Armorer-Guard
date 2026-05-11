import { spawnSync } from "node:child_process";

const guardBin = process.env.ARMORER_GUARD_BIN || "armorer-guard";

export function inspectWithArmorerGuard(text, context = {}) {
  const payload = JSON.stringify({ text: String(text || ""), context });
  const result = spawnSync(guardBin, ["inspect-json"], {
    input: payload,
    encoding: "utf8",
    timeout: 2000,
  });

  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || "Armorer Guard failed");
  }
  return JSON.parse(result.stdout);
}

export function requireSafeToolArgs(toolName, toolArgs) {
  const verdict = inspectWithArmorerGuard(JSON.stringify(toolArgs), {
    eval_surface: "tool_call_args",
    trace_stage: "action",
    tool_name: toolName,
  });

  if (verdict.suspicious) {
    const error = new Error(`Armorer Guard blocked ${toolName}`);
    error.verdict = verdict;
    throw error;
  }
  return verdict.sanitized_text;
}

// Express/Vercel-style request guard.
export function armorerGuardMiddleware(req, res, next) {
  try {
    const verdict = inspectWithArmorerGuard(JSON.stringify(req.body || {}), {
      eval_surface: "request_body",
      trace_stage: "context_ingress",
      destination: req.path,
    });
    req.armorerGuard = verdict;
    if (verdict.suspicious) {
      return res.status(400).json({ error: "blocked_by_armorer_guard", verdict });
    }
    return next();
  } catch (error) {
    return res.status(500).json({ error: String(error.message || error) });
  }
}

