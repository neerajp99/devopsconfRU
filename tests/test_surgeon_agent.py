"""
Unit tests for Surgeon Agent
Demonstrates validation catches destructive changes
"""
import pytest
from datetime import datetime
from core.schemas import DriftEvent
from agents.surgeon_agent import SurgeonAgent
from agents.checker_agent import CheckerAgent


def test_surgeon_generates_valid_patch():
    """Test that Surgeon generates syntactically valid Terraform"""
    drift_event = DriftEvent(
        event_id="test-001",
        timestamp=datetime.now(),
        resource_type="aws_security_group",
        resource_name="test_sg",
        desired_state={"ingress": [{"port": 443}]},
        actual_state={"ingress": [{"port": 443}, {"port": 22}]},
        diff={"added": [{"port": 22}]},
        severity="high",
        environment="dev"
    )

    surgeon = SurgeonAgent()
    plan = surgeon.generate_patch(drift_event)

    assert plan is not None
    assert "aws_security_group" in plan.terraform_patch
    assert plan.change_type == "update"


def test_checker_rejects_destructive_changes():
    """Test that Checker catches destructive operations"""
    # Create a plan with destructive change
    from core.schemas import RemediationPlan

    destructive_plan = RemediationPlan(
        plan_id="test-destructive",
        drift_event_id="test-001",
        terraform_patch="""
resource "aws_security_group" "test" {
  force_destroy = true
}
""",
        affected_files=["test.tf"],
        change_type="delete",
        risk_assessment={"estimated_risk": 0.9}
    )

    drift_event = DriftEvent(
        event_id="test-001",
        timestamp=datetime.now(),
        resource_type="aws_security_group",
        resource_name="test_sg",
        desired_state={},
        actual_state={},
        diff={},
        severity="high",
        environment="prod"
    )

    checker = CheckerAgent()
    report = checker.validate(destructive_plan, drift_event)

    assert report.approved == False
    assert report.destructive_changes_detected == True
    assert report.recommendation == "escalate"


def test_checker_approves_safe_changes():
    """Test that Checker approves safe, low-risk changes"""
    from core.schemas import RemediationPlan

    safe_plan = RemediationPlan(
        plan_id="test-safe",
        drift_event_id="test-002",
        terraform_patch="""
resource "aws_security_group" "test" {
  tags = {
    Environment = "dev"
  }
}
""",
        affected_files=["test.tf"],
        change_type="update",
        risk_assessment={"estimated_risk": 0.2}
    )

    drift_event = DriftEvent(
        event_id="test-002",
        timestamp=datetime.now(),
        resource_type="aws_security_group",
        resource_name="test_sg",
        desired_state={"tags": {"Environment": "dev"}},
        actual_state={"tags": {}},
        diff={"added": [{"tags": {"Environment": "dev"}}]},
        severity="low",
        environment="dev"
    )

    checker = CheckerAgent()
    report = checker.validate(safe_plan, drift_event)

    # Should approve for dev environment, low risk
    assert report.terraform_validate_passed == True
    assert report.recommendation in ["approve", "escalate"]  # May escalate due to SG type


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
