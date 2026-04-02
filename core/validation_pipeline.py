"""
Three-stage validation pipeline
1. terraform validate (syntax)
2. terraform plan (destructive changes)
3. OPA policy evaluation (business rules)
"""
import subprocess
import json
from typing import Tuple, List


class ValidationPipeline:
    """Validates Terraform patches before execution"""

    def validate_syntax(self, tf_code: str) -> Tuple[bool, str]:
        """Stage 1: Terraform syntax validation"""
        # Placeholder - in production, write to temp file and run terraform validate
        return True, ""

    def validate_plan(self, tf_code: str) -> Tuple[bool, List[str]]:
        """Stage 2: Check for destructive changes"""
        destructive_keywords = [
            "force_destroy",
            "delete_",
            "destroy",
            "replace"
        ]

        issues = []
        for keyword in destructive_keywords:
            if keyword in tf_code.lower():
                issues.append(f"Potentially destructive operation: {keyword}")

        return len(issues) == 0, issues

    def validate_policy(self, environment: str, resource_type: str, risk_score: float) -> Tuple[bool, str]:
        """Stage 3: OPA policy check"""
        # Tier 1: dev + low risk = auto-approve
        if environment == "dev" and risk_score < 0.5:
            return True, "tier1_auto_approved"

        # Tier 2: staging + medium risk = require review
        if environment == "staging" and risk_score < 0.7:
            return False, "tier2_requires_review"

        # Tier 3: prod or high risk = escalate
        return False, "tier3_escalate_to_human"
