"""
Detective Agent - Read-only RCA analysis
Uses LangGraph for orchestration, constrained by read-only IAM
Now with structured prompt templates and output validation
"""
import json
import os
from datetime import datetime
from typing import Dict
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI, AzureChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from core.schemas import DriftEvent, RCAReport
from templates import get_detective_prompt


class DetectiveAgent:
    """AI agent for root cause analysis - read-only operations"""

    def __init__(self, model="gpt-4o"):
        """
        Initialize Detective Agent with Azure OpenAI or standard OpenAI

        Checks for Azure credentials first, falls back to standard OpenAI
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
            print("[INFO] Detective Agent using Azure OpenAI")
        else:
            # Fall back to standard OpenAI
            self.llm = ChatOpenAI(model=model, temperature=0.1)
            print("[INFO] Detective Agent using standard OpenAI")

        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Build LangGraph workflow for RCA"""
        workflow = StateGraph(Dict)

        workflow.add_node("analyze_drift", self._analyze_drift)
        workflow.add_node("calculate_blast_radius", self._calculate_blast_radius)
        workflow.add_node("generate_report", self._generate_report)

        workflow.set_entry_point("analyze_drift")
        workflow.add_edge("analyze_drift", "calculate_blast_radius")
        workflow.add_edge("calculate_blast_radius", "generate_report")
        workflow.add_edge("generate_report", END)

        return workflow.compile()

    def _analyze_drift(self, state: Dict) -> Dict:
        """Analyze drift event and identify root cause using structured template"""
        drift_event: DriftEvent = state["drift_event"]

        # Load structured prompt template
        base_prompt = get_detective_prompt()

        # Fill in the drift event details
        prompt = f"""{base_prompt}

CURRENT DRIFT EVENT TO ANALYZE:

Resource Information:
- Type: {drift_event.resource_type}
- ID: {drift_event.resource_id}
- Environment: {drift_event.tags.get("environment", "unknown")}
- Severity: {drift_event.severity}

Desired State (what Terraform expects):
{json.dumps(drift_event.desired_state, indent=2)}

Actual State (what exists in cloud):
{json.dumps(drift_event.actual_state, indent=2)}

Diff (what changed):
{json.dumps(drift_event.diff, indent=2)}

Analyze this drift and output JSON following the format specified above.
"""

        response = self.llm.invoke([
            SystemMessage(content="You are a Senior DevOps Detective. Output valid JSON only, no markdown."),
            HumanMessage(content=prompt)
        ])

        # Parse and validate response
        try:
            analysis = json.loads(response.content)

            # Validate required fields
            required_fields = ["root_cause", "trigger_type", "confidence", "risk_assessment"]
            for field in required_fields:
                if field not in analysis:
                    raise ValueError(f"Missing required field: {field}")

            # Validate risk scores are in range
            if not (0.0 <= analysis["risk_assessment"]["overall_risk_score"] <= 1.0):
                raise ValueError("Risk score must be between 0.0 and 1.0")

        except (json.JSONDecodeError, ValueError) as e:
            # Fallback to simple analysis if structured response fails
            analysis = {
                "root_cause": f"Drift detected in {drift_event.resource_type}",
                "trigger_type": "manual",
                "confidence": 0.5,
                "risk_assessment": {
                    "overall_risk_score": 0.5,
                    "security_risk": 0.5,
                    "availability_risk": 0.3,
                    "compliance_risk": 0.2
                }
            }

        state["analysis"] = analysis
        return state

    def _calculate_blast_radius(self, state: Dict) -> Dict:
        """Calculate impact radius of the drift"""
        drift_event: DriftEvent = state["drift_event"]

        # Simple heuristic - in production, query actual dependency graph
        blast_radius = {
            "security_groups": 0,
            "instances": 0,
            "load_balancers": 0
        }

        if drift_event.resource_type == "aws_security_group":
            blast_radius["security_groups"] = 1
            # Assume 5 instances per security group
            blast_radius["instances"] = 5

        state["blast_radius"] = blast_radius
        return state

    def _generate_report(self, state: Dict) -> Dict:
        """Generate final RCA report with structured output"""
        drift_event: DriftEvent = state["drift_event"]
        analysis = state["analysis"]
        blast_radius = state["blast_radius"]

        # Extract risk score from structured analysis
        risk_assessment = analysis.get("risk_assessment", {})
        risk_score = risk_assessment.get("overall_risk_score", 0.5)

        # Extract recommended action or derive from trigger type
        recommended_action = analysis.get("recommended_action", "restore_desired_state")
        if not recommended_action and "trigger_type" in analysis:
            trigger = analysis["trigger_type"]
            if trigger == "manual":
                recommended_action = "restore_desired_state"
            elif trigger == "automation":
                recommended_action = "investigate_automation"
            elif trigger == "cascade":
                recommended_action = "escalate_to_security"
            else:
                recommended_action = "restore_desired_state"

        report = RCAReport(
            drift_event_id=drift_event.event_id,
            root_cause=analysis["root_cause"],
            affected_resources=[f"{drift_event.resource_type}.{drift_event.resource_id}"],
            blast_radius=blast_radius,
            correlation_score=analysis.get("confidence", 0.7),
            recommended_action=recommended_action,
            risk_score=risk_score,
            generated_at=datetime.now()
        )

        state["rca_report"] = report
        return state

    def analyze(self, drift_event: DriftEvent) -> RCAReport:
        """Main entry point for RCA analysis"""
        result = self.graph.invoke({
            "drift_event": drift_event
        })
        return result["rca_report"]
