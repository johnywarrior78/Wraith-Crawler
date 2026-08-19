from __future__ import annotations

from enum import StrEnum


class PluginState(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    NOT_APPLICABLE = "not_applicable"
    BLOCKED = "blocked"


class FailureReason(StrEnum):
    TARGET_UNREACHABLE = "target_unreachable"
    DEPENDENCY_FAILED = "dependency_failed"
    REQUIRED_CAPABILITY_UNAVAILABLE = "required_capability_unavailable"
    TOOL_MISSING = "tool_missing"
    TOOL_EXECUTION_FAILED = "tool_execution_failed"
    TIMEOUT = "timeout"
    WAF_OR_RATE_LIMIT = "waf_or_rate_limit"
    PARSING_ERROR = "parsing_error"
    CONFIGURATION_ERROR = "configuration_error"
    INTERNAL_PLUGIN_ERROR = "internal_plugin_error"
    INVALID_INPUT = "invalid_input"
    INCOMPLETE_RESPONSE = "incomplete_response"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SPECULATIVE = "speculative"


class ValidationStatus(StrEnum):
    CANDIDATE = "candidate"
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    MANUAL_REVIEW = "manual_review"
    FALSE_POSITIVE = "false_positive"


class FindingStatus(StrEnum):
    NEW = "new"
    OPEN = "open"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    RECURRING = "recurring"


class AssessmentStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class PentestPhase(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION_VALIDATION = "exploitation_validation"
    ANALYSIS = "analysis"
    ATTACK_PATH = "attack_path"
    POST_EXPLOITATION_REASONING = "post_exploitation_reasoning"
    REPORTING = "reporting"

    @property
    def order(self) -> int:
        return tuple(PentestPhase).index(self)


class RoleName(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class AttackNodeType(StrEnum):
    ATTACKER = "attacker"
    DOMAIN_APPLICATION = "domain_application"
    ENDPOINT_API = "endpoint_api"
    PARAMETER = "parameter"
    AUTHENTICATION_BOUNDARY = "authentication_boundary"
    VULNERABILITY = "vulnerability"
    SECRET_CREDENTIAL = "secret_credential"  # noqa: S105 - domain node type, not a secret
    SESSION_ACCOUNT = "session_account"
    ADMINISTRATIVE_FUNCTION = "administrative_function"
    DATABASE_STORAGE = "database_storage"
    SERVICE_CLOUD_SERVICE = "service_cloud_service"
    SENSITIVE_DATA = "sensitive_data"
    TECHNOLOGY = "technology"
    SECURITY_CONTROL = "security_control"
    ATTACKER_CAPABILITY = "attacker_capability"


class AttackPathStatus(StrEnum):
    NEW = "new"
    UNCHANGED = "unchanged"
    EXPANDED = "expanded"
    REDUCED = "reduced"
    BROKEN = "broken"
    RESOLVED = "resolved"


class ScanProfile(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    DISCOVERY_ONLY = "discovery_only"
