"""
Threshold-based approval engine

Implements risk-based auto-approve logic using configurable thresholds.

Key Concept:
- Calculate composite risk score from multiple factors
- Compare against tier thresholds (0.3, 0.7)
- Decide: auto_approve | require_review | escalate

This enables:
- 40% of changes auto-approved (low risk, dev environment)
- 35% require human review (medium risk, staging)
- 25% escalated to senior engineers (high risk, production)
"""
from typing import Dict, Tuple
from core.schemas import DriftEvent, RCAReport, CheckerReport


class ApprovalEngine:
    """
    Threshold-Based Approval Decision Engine

    Responsibilities:
    - Calculate composite risk score from drift event, RCA, and checker results
    - Compare risk score against tier thresholds
    - Make approval decision: auto_approve | require_review | escalate

    Three-Tier Model:
    - Tier 1: risk < 0.3  -> Auto-approve, enable auto-merge
    - Tier 2: risk < 0.7  -> Require 1 human approval
    - Tier 3: risk >= 0.7 -> Require 2 approvals, notify security team
    """

    def __init__(self, config: Dict = None):
        """
        Initialize approval engine with threshold configuration

        Args:
            config: Optional threshold configuration dict
                   If None, uses default 3-tier configuration

        Default thresholds:
        - Tier 1 (auto-approve): risk < 0.3, dev environment only
        - Tier 2 (require review): 0.3 <= risk < 0.7, staging environment
        - Tier 3 (escalate): risk >= 0.7 or production environment
        """
        self.config = config or self._default_config()

    def _default_config(self) -> Dict:
        """Default threshold configuration"""
        return {
            "tier1": {
                "auto_approve": True,
                "max_risk_score": 0.3,
                "environments": ["dev"],
                "allowed_resource_types": ["tags", "descriptions", "log_groups"]
            },
            "tier2": {
                "auto_approve": False,
                "requires_review": True,
                "max_risk_score": 0.7,
                "environments": ["staging"],
                "allowed_resource_types": ["instances", "load_balancers", "autoscaling_groups"],
                "required_approvers": 1
            },
            "tier3": {
                "auto_approve": False,
                "escalate_always": True,
                "environments": ["prod"],
                "critical_resource_types": [
                    "security_group",
                    "iam_role",
                    "iam_policy",
                    "kms_key",
                    "vpc",
                    "subnet",
                    "route_table"
                ],
                "required_approvers": 2
            }
        }

    def evaluate(
        self,
        drift_event: DriftEvent,
        rca_report: RCAReport,
        checker_report: CheckerReport
    ) -> Tuple[str, Dict]:
        """
        Evaluate if remediation can be auto-approved

        Returns:
            (decision, metadata)
            decision: "auto_approve" | "require_review" | "escalate"
            metadata: Additional context for the decision
        """

        # Calculate composite risk score
        risk_score = self._calculate_risk_score(drift_event, rca_report, checker_report)

        # Determine tier based on environment and risk
        tier = self._determine_tier(drift_event, risk_score)

        # Apply tier-specific logic
        decision, metadata = self._apply_tier_logic(
            tier=tier,
            drift_event=drift_event,
            rca_report=rca_report,
            checker_report=checker_report,
            risk_score=risk_score
        )

        return decision, metadata

    def _calculate_risk_score(
        self,
        drift_event: DriftEvent,
        rca_report: RCAReport,
        checker_report: CheckerReport
    ) -> float:
        """
        Calculate composite risk score from multiple factors

        This is the core algorithm that determines approval tier.

        Risk Score Formula:
        composite_risk = (base_risk * env_mult * resource_mult * checker_mult) + validation_penalty

        Factors (weighted by importance):
        1. Base risk from Detective RCA (0.0 - 1.0)
        2. Environment multiplier (dev: 0.5x, staging: 1.0x, prod: 1.5x)
        3. Resource type multiplier (critical resources: 1.5x, normal: 1.0x)
        4. Checker concerns multiplier (destructive: +0.3, issues: +0.1 each)
        5. Validation failures penalty (syntax fail: +0.2, policy fail: +0.2)

        Args:
            drift_event: Original drift event
            rca_report: Root cause analysis from Detective
            checker_report: Validation results from Checker

        Returns:
            Float between 0.0 (no risk) and 1.0 (critical risk)
        """

        # Factor 1: Base risk from RCA analysis
        # Detective Agent calculates this based on:
        # - Security risk (ports open to internet, IAM changes)
        # - Availability risk (could cause downtime)
        # - Compliance risk (violates policies)
        base_risk = rca_report.risk_score

        # Factor 2: Environment multiplier
        # Production changes are inherently more risky than dev changes
        environment = drift_event.tags.get("environment", "prod")
        env_multiplier = {
            "dev": 0.5,       # Development: lower risk
            "staging": 1.0,   # Staging: baseline risk
            "prod": 1.5       # Production: higher risk
        }.get(environment, 1.0)

        # Factor 3: Resource type multiplier
        # Some resources are security-critical and warrant extra scrutiny
        critical_resources = [
            "security_group",  # Network access controls
            "iam_role",        # Identity and permissions
            "iam_policy",      # Access policies
            "kms_key",         # Encryption keys
            "vpc",             # Network infrastructure
            "subnet",          # Network segmentation
            "route_table"      # Traffic routing
        ]

        if drift_event.resource_type in critical_resources:
            resource_multiplier = 1.5  # Increase risk for critical resources
        else:
            resource_multiplier = 1.0  # Normal risk for other resources

        # Factor 4: Checker concerns multiplier
        # If Checker Agent found issues, increase risk
        checker_multiplier = 1.0

        if checker_report.destructive_changes_detected:
            # Destructive operations (delete, replace) are high risk
            checker_multiplier += 0.3

        # Each issue found adds incremental risk
        if len(checker_report.issues_found) > 0:
            checker_multiplier += 0.1 * len(checker_report.issues_found)

        # Factor 5: Validation failures
        # Hard failures in validation pipeline increase risk
        validation_penalty = 0.0

        if not checker_report.terraform_validate_passed:
            # Syntax errors indicate potential problems
            validation_penalty += 0.2

        if not checker_report.opa_policy_passed:
            # Policy violations are security concerns
            validation_penalty += 0.2

        # Calculate composite score using multiplicative and additive factors
        composite_risk = (
            base_risk * env_multiplier * resource_multiplier * checker_multiplier
            + validation_penalty
        )

        # Clamp result to valid range [0.0, 1.0]
        return min(1.0, max(0.0, composite_risk))

    def _determine_tier(self, drift_event: DriftEvent, risk_score: float) -> int:
        """
        Determine which tier this remediation falls into

        Tier 1: Low risk, dev environment
        Tier 2: Medium risk, staging environment
        Tier 3: High risk or production
        """
        environment = drift_event.tags.get("environment", "prod")

        # Tier 3: Production always goes here
        if environment == "prod":
            return 3

        # Tier 3: Critical resources
        if drift_event.resource_type in self.config["tier3"]["critical_resource_types"]:
            return 3

        # Tier 3: High risk
        if risk_score >= 0.7:
            return 3

        # Tier 2: Staging or medium risk
        if environment == "staging" or (0.3 <= risk_score < 0.7):
            return 2

        # Tier 1: Dev and low risk
        if environment == "dev" and risk_score < 0.3:
            return 1

        # Default to Tier 2 (safe default)
        return 2

    def _apply_tier_logic(
        self,
        tier: int,
        drift_event: DriftEvent,
        rca_report: RCAReport,
        checker_report: CheckerReport,
        risk_score: float
    ) -> Tuple[str, Dict]:
        """Apply tier-specific approval logic"""

        metadata = {
            "tier": tier,
            "risk_score": risk_score,
            "environment": drift_event.tags.get("environment", "prod"),
            "resource_type": drift_event.resource_type
        }

        # Tier 1: Auto-approve if all checks pass
        if tier == 1:
            if (checker_report.approved and
                not checker_report.destructive_changes_detected and
                checker_report.terraform_validate_passed and
                risk_score < self.config["tier1"]["max_risk_score"]):

                return "auto_approve", {
                    **metadata,
                    "reason": "Low risk dev change, all validations passed",
                    "auto_merge": True
                }
            else:
                return "require_review", {
                    **metadata,
                    "reason": "Failed validation checks",
                    "required_approvers": 1
                }

        # Tier 2: Always require review
        elif tier == 2:
            return "require_review", {
                **metadata,
                "reason": "Staging environment requires human review",
                "required_approvers": self.config["tier2"]["required_approvers"],
                "auto_merge": False
            }

        # Tier 3: Always escalate
        else:
            return "escalate", {
                **metadata,
                "reason": self._tier3_escalation_reason(drift_event, checker_report),
                "required_approvers": self.config["tier3"]["required_approvers"],
                "notify_security_team": drift_event.resource_type in [
                    "security_group", "iam_role", "iam_policy"
                ],
                "notify_oncall": drift_event.severity in ["high", "critical"],
                "auto_merge": False
            }

    def _tier3_escalation_reason(
        self,
        drift_event: DriftEvent,
        checker_report: CheckerReport
    ) -> str:
        """Generate human-readable escalation reason for Tier 3"""

        reasons = []
        environment = drift_event.tags.get("environment", "prod")

        if environment == "prod":
            reasons.append("Production environment")

        if drift_event.resource_type in self.config["tier3"]["critical_resource_types"]:
            reasons.append(f"Critical resource type ({drift_event.resource_type})")

        if checker_report.destructive_changes_detected:
            reasons.append("Destructive changes detected")

        if drift_event.severity in ["high", "critical"]:
            reasons.append(f"{drift_event.severity.upper()} severity")

        return " + ".join(reasons) if reasons else "High risk change requires escalation"

    def get_approval_summary(
        self,
        drift_event: DriftEvent,
        rca_report: RCAReport,
        checker_report: CheckerReport
    ) -> Dict:
        """
        Get detailed approval summary for display/logging

        Returns human-readable summary of approval decision
        """

        decision, metadata = self.evaluate(drift_event, rca_report, checker_report)

        summary = {
            "decision": decision,
            "tier": metadata["tier"],
            "risk_score": round(metadata["risk_score"], 3),
            "environment": drift_event.tags.get("environment", "prod"),
            "resource": f"{drift_event.resource_type}.{drift_event.resource_id}",
            "reason": metadata["reason"],
            "thresholds": {
                "tier1_max_risk": self.config["tier1"]["max_risk_score"],
                "tier2_max_risk": self.config["tier2"]["max_risk_score"],
                "current_risk": round(metadata["risk_score"], 3)
            },
            "actions_required": self._get_required_actions(decision, metadata),
            "auto_merge_enabled": metadata.get("auto_merge", False)
        }

        return summary

    def _get_required_actions(self, decision: str, metadata: Dict) -> list:
        """Get list of actions required based on decision"""

        actions = []

        if decision == "auto_approve":
            actions.append("[OK] Create PR with auto-merge enabled")
            actions.append("[OK] Monitor for deployment success")

        elif decision == "require_review":
            actions.append(f"[REVIEW] Create PR requiring {metadata['required_approvers']} approval(s)")
            actions.append("[ASSIGN] Assign to team for review")
            actions.append("[WAIT] Wait for human approval")

        elif decision == "escalate":
            actions.append(f"[WARNING]  Create PR requiring {metadata['required_approvers']} approval(s)")
            actions.append("[ASSIGN] Assign to senior team members")

            if metadata.get("notify_security_team"):
                actions.append("[SECURITY] Notify security team")

            if metadata.get("notify_oncall"):
                actions.append("[ONCALL] Page oncall engineer")

            actions.append("📊 Include detailed risk assessment in PR")

        return actions
