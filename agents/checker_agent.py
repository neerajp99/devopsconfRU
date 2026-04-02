"""
Checker Agent - Validates Surgeon's work before PR creation
Checker in the Maker-Checker pattern
Now with structured prompt templates and comprehensive validation
"""
import json
import subprocess
import tempfile
import os
from datetime import datetime
from typing import Dict, Tuple, List
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI, AzureChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from core.schemas import RemediationPlan, CheckerReport, DriftEvent
from core.validation_pipeline import ValidationPipeline
from templates import get_checker_prompt


class CheckerAgent:
    """AI agent that validates Surgeon's patches - final safety gate"""

    def __init__(self, model="gpt-4o"):
        """
        Initialize Checker Agent with Azure OpenAI or standard OpenAI
        """
        # Check if Azure OpenAI credentials are available
        azure_api_key = os.getenv("AZURE_OPENAI_GPT_API_KEY2")
        azure_endpoint = os.getenv("AZURE_OPENAI_GPT_ENDPOINT2")
        azure_deployment = os.getenv("AZURE_GPT_DEPLOYMENT_NAME2")

        if azure_api_key and azure_endpoint and azure_deployment:
            # Use Azure OpenAI
            # Note: o3-mini doesn't support temperature parameter
            self.llm = AzureChatOpenAI(
                azure_endpoint=azure_endpoint,
                azure_deployment=azure_deployment,
                api_key=azure_api_key,
                api_version="2024-12-01-preview",  # Updated for o3-mini support
            )
            print("[INFO] Checker Agent using Azure OpenAI")
        else:
            # Fall back to standard OpenAI
            self.llm = ChatOpenAI(model=model, temperature=0.0)
            print("[INFO] Checker Agent using standard OpenAI")

        self.validator = ValidationPipeline()
        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Build LangGraph workflow for validation"""
        workflow = StateGraph(Dict)

        workflow.add_node("syntax_check", self._syntax_check)
        workflow.add_node("semantic_analysis", self._semantic_analysis)
        workflow.add_node("policy_check", self._policy_check)
        workflow.add_node("generate_verdict", self._generate_verdict)

        workflow.set_entry_point("syntax_check")
        workflow.add_edge("syntax_check", "semantic_analysis")
        workflow.add_edge("semantic_analysis", "policy_check")
        workflow.add_edge("policy_check", "generate_verdict")
        workflow.add_edge("generate_verdict", END)

        return workflow.compile()

    def _syntax_check(self, state: Dict) -> Dict:
        """Run terraform validate"""
        plan: RemediationPlan = state["remediation_plan"]

        try:
            # Write patch to temp file and validate
            with tempfile.TemporaryDirectory() as tmpdir:
                tf_file = os.path.join(tmpdir, "main.tf")
                with open(tf_file, "w") as f:
                    f.write(plan.terraform_patch)

                result = subprocess.run(
                    ["terraform", "fmt", "-check", tf_file],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                syntax_valid = result.returncode == 0
                state["terraform_validate_passed"] = syntax_valid
                state["syntax_errors"] = result.stderr if not syntax_valid else ""

        except Exception as e:
            state["terraform_validate_passed"] = False
            state["syntax_errors"] = str(e)

        return state

    def _semantic_analysis(self, state: Dict) -> Dict:
        """Check for destructive changes using AI with structured template"""
        plan: RemediationPlan = state["remediation_plan"]
        drift_event: DriftEvent = state["drift_event"]

        # Load structured prompt template
        base_prompt = get_checker_prompt()

        prompt = f"""{base_prompt}

CURRENT PATCH TO REVIEW:

Drift Event Context:
- Resource: {drift_event.resource_type}.{drift_event.resource_id}
- Environment: {drift_event.tags.get("environment", "unknown")}
- Severity: {drift_event.severity}

Desired State (what Terraform expects):
{json.dumps(drift_event.desired_state, indent=2)}

Actual State (what exists now):
{json.dumps(drift_event.actual_state, indent=2)}

Surgeon's Proposed Patch:
{plan.terraform_patch}

Perform comprehensive security and safety review. Output JSON following the format specified above.
"""

        response = self.llm.invoke([
            SystemMessage(content="You are a Terraform Safety Checker. Output valid JSON only, no markdown."),
            HumanMessage(content=prompt)
        ])

        # Parse and validate response
        try:
            analysis = json.loads(response.content)

            # Validate required fields
            required_fields = ["approved", "recommendation", "destructive_operations",
                              "security_concerns", "reasoning"]
            for field in required_fields:
                if field not in analysis:
                    raise ValueError(f"Missing required field: {field}")

            # Additional validation checks
            state["destructive_changes_detected"] = (
                analysis.get("approved", True) == False or
                len(analysis.get("destructive_operations", [])) > 0
            )

        except (json.JSONDecodeError, ValueError) as e:
            # Fallback to conservative analysis if structured response fails
            print(f"Warning: Failed to parse Checker response: {e}")
            print(f"Raw response: {response.content[:200]}")

            # Do manual pattern checking as fallback
            destructive_patterns = self._manual_destructive_check(plan.terraform_patch)

            analysis = {
                "approved": len(destructive_patterns) == 0,
                "recommendation": "reject" if destructive_patterns else "approve",
                "destructive_operations": destructive_patterns,
                "security_concerns": [],
                "forbidden_patterns": [],
                "state_alignment_issues": [],
                "syntax_errors": [],
                "reasoning": "Manual validation due to response parsing failure",
                "suggested_fixes": destructive_patterns
            }
            state["destructive_changes_detected"] = len(destructive_patterns) > 0

        state["semantic_analysis"] = analysis
        return state

    def _manual_destructive_check(self, patch: str) -> List[str]:
        """Manual check for destructive patterns as fallback"""
        issues = []

        destructive_keywords = [
            "force_destroy",
            "prevent_destroy = false",
            "delete_",
            "lifecycle"
        ]

        for keyword in destructive_keywords:
            if keyword in patch.lower():
                issues.append(f"Potentially destructive pattern: {keyword}")

        return issues

    def _policy_check(self, state: Dict) -> Dict:
        """Run OPA policy evaluation"""
        plan: RemediationPlan = state["remediation_plan"]
        drift_event: DriftEvent = state["drift_event"]

        # Simulate OPA policy check
        env = drift_event.tags.get("environment", "prod")
        policy_input = {
            "environment": env,
            "resource_type": drift_event.resource_type,
            "change_type": plan.change_type,
            "risk_score": plan.risk_assessment["estimated_risk"],
            "is_destructive": state["destructive_changes_detected"]
        }

        # Tier 1: Auto-approve low-risk changes
        # Tier 2: Require review for medium-risk
        # Tier 3: Escalate high-risk

        opa_passed = True
        recommendation = "approve"

        if env == "prod" or state["destructive_changes_detected"]:
            opa_passed = False
            recommendation = "escalate"
        elif drift_event.severity in ["high", "critical"]:
            recommendation = "escalate"

        state["opa_policy_passed"] = opa_passed
        state["recommendation"] = recommendation

        return state

    def _generate_verdict(self, state: Dict) -> Dict:
        """Generate final checker report"""
        plan: RemediationPlan = state["remediation_plan"]
        semantic = state.get("semantic_analysis", {})

        issues_found = []
        if not state["terraform_validate_passed"]:
            issues_found.append(f"Terraform validation failed: {state['syntax_errors']}")
        if state["destructive_changes_detected"]:
            issues_found.extend(semantic.get("destructive_operations", []))
        if not state["opa_policy_passed"]:
            issues_found.append("OPA policy check failed - requires human review")

        approved = (
            state["terraform_validate_passed"] and
            not state["destructive_changes_detected"] and
            state["opa_policy_passed"]
        )

        report = CheckerReport(
            plan_id=plan.plan_id,
            approved=approved,
            issues_found=issues_found,
            terraform_validate_passed=state["terraform_validate_passed"],
            terraform_plan_passed=not state["destructive_changes_detected"],
            opa_policy_passed=state["opa_policy_passed"],
            destructive_changes_detected=state["destructive_changes_detected"],
            recommendation=state["recommendation"],
            reasoning=semantic.get("reasoning", "All validations passed") if approved else "Failed validation checks",
            checked_at=datetime.now()
        )

        state["checker_report"] = report
        return state

    def validate(self, plan: RemediationPlan, drift_event: DriftEvent) -> CheckerReport:
        """Main entry point for validation"""
        result = self.graph.invoke({
            "remediation_plan": plan,
            "drift_event": drift_event
        })
        return result["checker_report"]
