"""Public client SDK for an Armorer-provisioned Guard runtime."""

from importlib.metadata import PackageNotFoundError, version

from .adapters import (
    CrewAIAdapter,
    HttpWebhookAdapter,
    LangGraphAdapter,
    OpenAIAgentsAdapter,
    OpenAICompatibleAdapter,
)
from .client import (
    GuardApprovalRequired,
    GuardDenied,
    GuardedExecution,
    GuardSidecar,
    GuardSidecarError,
    canonical_digest,
    canonical_json,
    protect_capability,
    sign_canonical,
)
from .contracts import (
    AuthorityRequest,
    ContentDecision,
    ContentEvaluationRequest,
    ContentFinding,
    ContentSegment,
)

try:
    __version__ = version("armorer-guard")
except PackageNotFoundError:
    __version__ = "1.0.0"

__all__ = [
    "AuthorityRequest",
    "ContentDecision",
    "ContentEvaluationRequest",
    "ContentFinding",
    "ContentSegment",
    "CrewAIAdapter",
    "GuardApprovalRequired",
    "GuardDenied",
    "GuardSidecar",
    "GuardSidecarError",
    "GuardedExecution",
    "HttpWebhookAdapter",
    "LangGraphAdapter",
    "OpenAIAgentsAdapter",
    "OpenAICompatibleAdapter",
    "canonical_digest",
    "canonical_json",
    "protect_capability",
    "sign_canonical",
]
