"""
Drift detector - monitors Terraform state vs actual cloud state
In production, integrates with AWS/GCP/Azure APIs
"""
import json
from datetime import datetime
from typing import Dict, List
from core.schemas import DriftEvent


class DriftDetector:
    """
    Detects drift between desired (Terraform) and actual (Cloud) state
    Runs on schedule (e.g., every 15 minutes via cron)
    """

    def __init__(self, cloud_provider: str = "aws"):
        self.cloud_provider = cloud_provider

    def detect_drift(self, terraform_state: Dict, actual_state: Dict) -> DriftEvent:
        """
        Compare Terraform state file with actual cloud resources
        Returns DriftEvent if mismatch detected
        """
        # Calculate diff
        diff = self._calculate_diff(terraform_state, actual_state)

        if not diff["added"] and not diff["removed"] and not diff["changed"]:
            return None  # No drift

        # Calculate severity
        severity = self._calculate_severity(diff, terraform_state)

        drift_event = DriftEvent(
            event_id=f"drift-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            timestamp=datetime.now(),
            resource_type=terraform_state.get("type", "unknown"),
            resource_name=terraform_state.get("name", "unknown"),
            desired_state=terraform_state,
            actual_state=actual_state,
            diff=diff,
            severity=severity,
            environment=terraform_state.get("tags", {}).get("Environment", "unknown")
        )

        return drift_event

    def _calculate_diff(self, desired: Dict, actual: Dict) -> Dict:
        """Calculate what changed between desired and actual"""
        diff = {
            "added": [],
            "removed": [],
            "changed": []
        }

        # Simple diff for demo - in production, use deep comparison
        for key in actual:
            if key not in desired:
                diff["added"].append({key: actual[key]})
            elif desired[key] != actual[key]:
                diff["changed"].append({
                    "key": key,
                    "desired": desired[key],
                    "actual": actual[key]
                })

        for key in desired:
            if key not in actual:
                diff["removed"].append({key: desired[key]})

        return diff

    def _calculate_severity(self, diff: Dict, state: Dict) -> str:
        """Calculate severity based on what changed"""
        resource_type = state.get("type", "")

        # Security-related resources are high severity
        if any(x in resource_type for x in ["security_group", "iam", "kms", "firewall"]):
            return "high"

        # Added rules are more severe than removed
        if diff["added"]:
            return "high"

        # Changed values
        if diff["changed"]:
            return "medium"

        # Removed rules
        if diff["removed"]:
            return "low"

        return "low"
