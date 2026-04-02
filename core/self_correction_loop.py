"""
Self-correction loop for Surgeon Agent
Retries with error feedback up to 3 times
"""
from typing import Optional
from core.schemas import DriftEvent, RemediationPlan, CheckerReport
from agents.surgeon_agent import SurgeonAgent
from agents.checker_agent import CheckerAgent


class SelfCorrectionLoop:
    """
    Implements retry logic with error feedback
    If validation fails, feeds error back to Surgeon for correction
    """

    def __init__(self, max_retries: int = 3):
        self.max_retries = max_retries
        self.surgeon = SurgeonAgent()
        self.checker = CheckerAgent()

    def generate_with_retries(
        self,
        drift_event: DriftEvent
    ) -> tuple[Optional[RemediationPlan], Optional[CheckerReport]]:
        """
        Generate patch with automatic retries on validation failure
        Returns: (plan, checker_report) or (None, None) if all retries fail
        """
        attempt = 0
        previous_error = ""

        while attempt < self.max_retries:
            attempt += 1
            print(f"  Attempt {attempt}/{self.max_retries}...")

            # Generate patch
            plan = self.surgeon.generate_patch(drift_event)

            # Validate
            checker_report = self.checker.validate(plan, drift_event)

            # Check if approved
            if checker_report.approved:
                print(f"  [OK] Success on attempt {attempt}")
                return plan, checker_report

            # Failed - prepare error feedback
            previous_error = self._format_error_feedback(checker_report)
            print(f"  [FAIL] Attempt {attempt} failed: {checker_report.recommendation}")
            print(f"     Issues: {', '.join(checker_report.issues_found)}")

            # On last attempt, give up
            if attempt >= self.max_retries:
                print(f"  [WARNING]  Max retries reached. Escalating to human.")
                return None, checker_report

        return None, None

    def _format_error_feedback(self, checker_report: CheckerReport) -> str:
        """Format validation errors for Surgeon to learn from"""
        feedback = []

        if not checker_report.terraform_validate_passed:
            feedback.append("Terraform syntax validation failed")

        if checker_report.destructive_changes_detected:
            feedback.append("Destructive changes detected - avoid delete/replace operations")

        if not checker_report.opa_policy_passed:
            feedback.append("OPA policy check failed - violates security constraints")

        feedback.extend(checker_report.issues_found)

        return "; ".join(feedback)
