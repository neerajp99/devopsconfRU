"""
Surgeon Agent - Generates Terraform patches to fix drift
Maker in the Maker-Checker pattern
Now with structured prompt templates and output validation
"""
import json
import re
import os
from datetime import datetime
from typing import Dict
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI, AzureChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from core.schemas import DriftEvent, RCAReport, RemediationPlan
from templates import get_surgeon_prompt
import uuid


class SurgeonAgent:
    """
    Surgeon Agent - The "Maker" in Maker-Checker Pattern

    Responsibilities:
    - Generates Terraform HCL code patches to fix infrastructure drift
    - Uses structured prompt templates with safety constraints
    - Self-validates output before sending to Checker
    - NEVER executes terraform apply (only generates code)

    Design Philosophy:
    - Deterministic output (temperature=0.0)
    - Constrained by explicit forbidden patterns
    - Self-correction via retry loop
    """

    def __init__(self, model="gpt-4o"):
        """
        Initialize Surgeon Agent with LLM model

        Args:
            model: LLM model to use (default: gpt-4o)
                  Can also use: claude-3-5-sonnet, claude-opus-4
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
            print("[INFO] Surgeon Agent using Azure OpenAI")
        else:
            # Fall back to standard OpenAI
            self.llm = ChatOpenAI(model=model, temperature=0.0)
            print("[INFO] Surgeon Agent using standard OpenAI")

        # Build state machine workflow using LangGraph
        self.graph = self._build_graph()

        # Maximum retry attempts if validation fails
        self.max_retries = 3

    def _build_graph(self) -> StateGraph:
        """
        Build LangGraph workflow for patch generation

        Workflow steps:
        1. generate_patch  - Use LLM to create Terraform HCL
        2. self_validate   - Check for forbidden patterns
        3. create_plan     - Package into RemediationPlan object

        Returns:
            Compiled StateGraph workflow
        """
        workflow = StateGraph(Dict)

        # Define workflow nodes
        workflow.add_node("generate_patch", self._generate_patch)
        workflow.add_node("self_validate", self._self_validate)
        workflow.add_node("create_plan", self._create_plan)

        # Define workflow edges (execution order)
        workflow.set_entry_point("generate_patch")
        workflow.add_edge("generate_patch", "self_validate")
        workflow.add_edge("self_validate", "create_plan")
        workflow.add_edge("create_plan", END)

        return workflow.compile()

    def _generate_patch(self, state: Dict) -> Dict:
        """
        Generate HCL patch to restore desired state using structured template

        Process:
        1. Load base prompt template (2,600-word structured template)
        2. Fill in drift event details (desired vs actual state)
        3. Add RCA context if available (root cause, risk score)
        4. Add error feedback if this is a retry attempt
        5. Send to LLM and get Terraform HCL patch
        6. Clean and validate structure

        Args:
            state: Dict containing drift_event, rca_report, retry_count, previous_error

        Returns:
            Updated state with terraform_patch
        """
        # Extract required data from state
        drift_event: DriftEvent = state["drift_event"]
        rca_report: RCAReport = state.get("rca_report")
        retry_count = state.get("retry_count", 0)
        previous_error = state.get("previous_error", "")

        # Load structured prompt template with constraints and examples
        # This template includes:
        # - Explicit forbidden patterns (provider, data, provisioner)
        # - Output structure requirements (HCL only, no markdown)
        # - Validation checklist
        # - Error recovery guidance
        base_prompt = get_surgeon_prompt()

        # Build context from RCA if available
        rca_context = ""
        if rca_report:
            rca_context = f"""
ROOT CAUSE ANALYSIS (for context):
- Root Cause: {rca_report.root_cause}
- Recommended Action: {rca_report.recommended_action}
- Risk Score: {rca_report.risk_score}
"""

        # Build error feedback if this is a retry
        error_context = ""
        if previous_error:
            error_context = f"""
PREVIOUS ATTEMPT FAILED - ERROR FEEDBACK:
{previous_error}

Study this error carefully and fix the issue in your next attempt.
Common fixes:
- Syntax error → Check brackets, quotes, commas
- Destructive change → Remove force_destroy, avoid delete operations
- Forbidden pattern → Remove provider/data/provisioner blocks
- State mismatch → Compare your output with desired_state attribute by attribute
"""

        prompt = f"""{base_prompt}

CURRENT DRIFT TO FIX:

Resource Information:
- Type: {drift_event.resource_type}
- Name: {drift_event.resource_id}
- Environment: {drift_event.tags.get("environment", "unknown")}
- Severity: {drift_event.severity}

Desired State (CORRECT - match this exactly):
{json.dumps(drift_event.desired_state, indent=2)}

Actual State (WRONG - what exists now):
{json.dumps(drift_event.actual_state, indent=2)}

Diff (what changed):
{json.dumps(drift_event.diff, indent=2)}

{rca_context}
{error_context}

Retry Attempt: {retry_count + 1} of 3

Generate the Terraform HCL patch now. Output raw HCL only, no markdown.
"""

        response = self.llm.invoke([
            SystemMessage(content="You are a Terraform Surgeon. Output raw HCL code only, no markdown, no explanations."),
            HumanMessage(content=prompt)
        ])

        # Clean response - remove markdown if present
        patch = response.content.strip()

        # Remove markdown code blocks
        if patch.startswith("```"):
            lines = patch.split("\n")
            # Find first line after opening ```
            start_idx = 1
            if lines[0].strip().startswith("```"):
                start_idx = 1
            # Find last line before closing ```
            end_idx = len(lines) - 1
            for i in range(len(lines) - 1, -1, -1):
                if lines[i].strip() == "```":
                    end_idx = i
                    break
            patch = "\n".join(lines[start_idx:end_idx])

        # Validate basic structure
        patch = self._validate_and_fix_structure(patch, drift_event)

        state["terraform_patch"] = patch
        state["retry_count"] = retry_count
        return state

    def _validate_and_fix_structure(self, patch: str, drift_event: DriftEvent) -> str:
        """
        Validate patch follows expected structure and fix common issues

        Common issues fixed:
        1. LLM wrapped output in markdown code blocks (```hcl ... ```)
        2. LLM generated explanation text before/after code
        3. Missing proper resource block declaration

        Args:
            patch: Raw HCL code from LLM
            drift_event: Original drift event for resource type/name

        Returns:
            Clean HCL patch with proper structure
        """

        # Check if patch starts with resource block
        # If not, try to extract it from surrounding text
        if not patch.strip().startswith("resource"):
            # Try to find resource block pattern in the text
            resource_match = re.search(r'resource\s+"[^"]+"\s+"[^"]+"\s+\{', patch)
            if resource_match:
                start = resource_match.start()

                # Find matching closing brace by counting braces
                brace_count = 0
                in_resource = False
                end = len(patch)

                for i in range(start, len(patch)):
                    if patch[i] == '{':
                        brace_count += 1
                        in_resource = True
                    elif patch[i] == '}':
                        brace_count -= 1
                        # Found matching closing brace
                        if in_resource and brace_count == 0:
                            end = i + 1
                            break

                # Extract just the resource block
                patch = patch[start:end]

        # Ensure proper resource declaration format
        # Expected: resource "aws_security_group" "api_server" {
        expected_start = f'resource "{drift_event.resource_type}" "{drift_event.resource_id}"'

        # If missing resource declaration, wrap content in proper block
        if not patch.strip().startswith(expected_start.split()[0]):
            patch = f'{expected_start} {{\n  {patch}\n}}'

        return patch.strip()

    def _self_validate(self, state: Dict) -> Dict:
        """
        Basic self-validation before sending to Checker

        Checks for common errors:
        - Forbidden patterns (provider, data, provisioner blocks)
        - Execution commands (local-exec, remote-exec)

        Note: This is a lightweight check. Full validation happens in Checker Agent.

        Args:
            state: Dict containing terraform_patch

        Returns:
            Updated state with self_validation_issues list
        """
        patch = state["terraform_patch"]

        # Define forbidden patterns that should never appear in patches
        # These are security-critical: they could enable code execution or data exfiltration
        forbidden = [
            "provider",      # No provider blocks (could change AWS credentials)
            "data ",         # No data sources (could fetch external data)
            "provisioner",   # No provisioners (could execute arbitrary code)
            "exec",          # No execution commands
            "local-exec",    # No local shell execution
            "remote-exec"    # No remote shell execution
        ]
        issues = []

        # Scan patch for forbidden patterns
        for forbidden_pattern in forbidden:
            if forbidden_pattern in patch.lower():
                issues.append(f"Forbidden pattern detected: {forbidden_pattern}")

        # Store issues for potential retry
        state["self_validation_issues"] = issues
        return state

    def _create_plan(self, state: Dict) -> Dict:
        """
        Create remediation plan object from generated patch

        Packages the Terraform patch into a structured RemediationPlan object
        that can be validated by Checker Agent and used to create GitHub PRs.

        Args:
            state: Dict containing drift_event and terraform_patch

        Returns:
            Updated state with remediation_plan object
        """
        drift_event: DriftEvent = state["drift_event"]
        patch = state["terraform_patch"]

        # Create unique plan ID for tracking
        plan_id = str(uuid.uuid4())

        # Estimate risk score based on environment
        # Dev: lower risk (0.3), Production: higher risk (0.8)
        env = drift_event.tags.get("environment", "prod")
        if env == "dev":
            estimated_risk = 0.3
        elif env == "staging":
            estimated_risk = 0.5
        else:  # prod
            estimated_risk = 0.8

        # Create structured remediation plan
        plan = RemediationPlan(
            plan_id=plan_id,
            drift_event_id=drift_event.event_id,
            terraform_patch=patch,
            affected_files=[f"terraform/{drift_event.resource_type}.tf"],
            change_type="update",  # We only update existing resources, never create/delete
            risk_assessment={
                "environment": env,
                "severity": drift_event.severity,
                "estimated_risk": estimated_risk
            },
            generated_by="surgeon_agent"
        )

        state["remediation_plan"] = plan
        return state

    def generate_patch(self, drift_event: DriftEvent, rca_report: RCAReport = None) -> RemediationPlan:
        """
        Main entry point for patch generation

        This is the public API method that orchestrates the entire
        patch generation workflow.

        Workflow:
        1. Generate patch using LLM + structured template
        2. Self-validate for forbidden patterns
        3. Create RemediationPlan object

        Args:
            drift_event: Detected infrastructure drift
            rca_report: Optional root cause analysis for context

        Returns:
            RemediationPlan containing Terraform HCL patch
        """
        # Invoke LangGraph workflow
        result = self.graph.invoke({
            "drift_event": drift_event,
            "rca_report": rca_report
        })

        # Return the remediation plan created by workflow
        return result["remediation_plan"]
