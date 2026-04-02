"""
Detective Agent - Read-only RCA analysis
We are uisng LangGraph for orchestration, constrained by read-only IAM

TODO: Integrate CloudTrail, OPA, graph DB (marked with [PRODUCTION])
"""
import json
import os
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from langgraph.graph import StateGraph, END
from langchain_openai import ChatOpenAI, AzureChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from core.schemas import DriftEvent, RCAReport
from templates import get_detective_prompt


# [PRODUCTION] CloudTrail action mapping for actor identification
RESOURCE_ACTION_MAP = {
    "aws_security_group": [
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "ModifySecurityGroupRules",
    ],
    "aws_iam_role": [
        "AttachRolePolicy",
        "PutRolePolicy",
        "UpdateAssumeRolePolicy",
    ],
    "aws_route_table": [
        "CreateRoute", "DeleteRoute", "ReplaceRoute",
    ],
    "aws_s3_bucket": [
        "PutBucketPolicy", "PutBucketAcl", "PutBucketEncryption",
    ],
}


class DetectiveAgent:
    """AI agent for root cause analysis - read-only operations"""

    def __init__(self, model="gpt-4o"):
        # Try Azure first, fall back to OpenAI
        azure_api_key = os.getenv("AZURE_OPENAI_GPT_API_KEY2")
        azure_endpoint = os.getenv("AZURE_OPENAI_GPT_ENDPOINT2")
        azure_deployment = os.getenv("AZURE_GPT_DEPLOYMENT_NAME2")

        if azure_api_key and azure_endpoint and azure_deployment:
            self.llm = AzureChatOpenAI(
                azure_endpoint=azure_endpoint,
                azure_deployment=azure_deployment,
                api_key=azure_api_key,
                api_version="2024-12-01-preview",
            )
            print("[INFO] Detective Agent using Azure OpenAI")
        else:
            self.llm = ChatOpenAI(model=model, temperature=0.1)
            print("[INFO] Detective Agent using standard OpenAI")

        # [PRODUCTION] TODO: Uncomment when integrations ready
        # self.cloudtrail = CloudTrailClient()
        # self.opa = OPAClient(url="http://opa-server:8181")
        # self.graph_db = Neo4jClient(uri="bolt://neo4j:7687")

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

    def _query_cloudtrail(self, resource_id: str, time_window: datetime,
                          actions: List[str]) -> Optional[Dict]:
        """
        [PRODUCTION] Query CloudTrail for actor identification
        Returns: {"arn": str, "action": str, "timestamp": str, "source_ip": str}
        """
        # [PRODUCTION] TODO: Implement CloudTrail lookup
        # try:
        #     response = self.cloudtrail.lookup_events(
        #         LookupAttributes=[
        #             {"AttributeKey": "ResourceName", "AttributeValue": resource_id}
        #         ],
        #         StartTime=time_window - timedelta(minutes=15),
        #         EndTime=time_window,
        #         MaxResults=50
        #     )
        #     for event in response.get("Events", []):
        #         if event["EventName"] in actions:
        #             return {
        #                 "arn": event.get("Username"),
        #                 "action": event["EventName"],
        #                 "timestamp": event["EventTime"],
        #                 "source_ip": event.get("SourceIPAddress")
        #             }
        # except Exception as e:
        #     print(f"[WARN] CloudTrail query failed: {e}")
        return None

    def _evaluate_opa_policies(self, drift_event: DriftEvent) -> List[str]:
        """
        [PRODUCTION] Evaluate OPA policies for compliance violations
        Returns: List of violated policy names
        """
        # [PRODUCTION] TODO: Implement OPA evaluation
        # try:
        #     response = self.opa.evaluate(
        #         policy="drift/violations",
        #         input={
        #             "resource_type": drift_event.resource_type,
        #             "actual_state": drift_event.actual_state,
        #             "desired_state": drift_event.desired_state,
        #             "environment": drift_event.tags.get("environment"),
        #             "severity": drift_event.severity
        #         }
        #     )
        #     return response.get("result", {}).get("violations", [])
        # except Exception as e:
        #     print(f"[WARN] OPA evaluation failed: {e}")
        return []

    def _analyze_drift(self, state: Dict) -> Dict:
        """Analyze drift event and identify root cause using structured template"""
        drift_event: DriftEvent = state["drift_event"]

        # [PRODUCTION] TODO: Query external systems
        # actor = self._query_cloudtrail(
        #     resource_id=drift_event.resource_id,
        #     time_window=drift_event.detected_at,
        #     actions=RESOURCE_ACTION_MAP.get(drift_event.resource_type, [])
        # )
        # violations = self._evaluate_opa_policies(drift_event)

        # Load structured prompt template
        base_prompt = get_detective_prompt()

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

        # [PRODUCTION] TODO: Enrich prompt with CloudTrail + OPA data
        # if actor:
        #     prompt += f"\n\nCloudTrail: {actor['arn']} via {actor['action']} at {actor['timestamp']}"
        # if violations:
        #     prompt += f"\n\nOPA Violations: {', '.join(violations)}"

        response = self.llm.invoke([
            SystemMessage(content="You are a Senior DevOps Detective. Output valid JSON only, no markdown."),
            HumanMessage(content=prompt)
        ])

        # Parse and validate response
        try:
            analysis = json.loads(response.content)

            required_fields = ["root_cause", "trigger_type", "confidence", "risk_assessment"]
            for field in required_fields:
                if field not in analysis:
                    raise ValueError(f"Missing required field: {field}")

            if not (0.0 <= analysis["risk_assessment"]["overall_risk_score"] <= 1.0):
                raise ValueError("Risk score must be between 0.0 and 1.0")

        except (json.JSONDecodeError, ValueError) as e:
            print(f"[WARN] LLM analysis parsing failed: {e}")
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

        # Simple heuristic for demo
        blast_radius = {
            "security_groups": 0,
            "instances": 0,
            "load_balancers": 0
        }

        if drift_event.resource_type == "aws_security_group":
            blast_radius["security_groups"] = 1
            blast_radius["instances"] = 5  # Hardcoded for demo

        # [PRODUCTION] TODO: Query graph database
        # query = """
        # MATCH (source {resource_id: $resource_id})-[*1..3]->(downstream)
        # RETURN DISTINCT downstream.resource_type AS type, downstream.resource_id AS id
        # """
        # results = self.graph_db.run(query, resource_id=drift_event.resource_id)
        # blast_radius = {}
        # for record in results:
        #     resource_type = record["type"]
        #     blast_radius[resource_type] = blast_radius.get(resource_type, 0) + 1

        state["blast_radius"] = blast_radius
        return state

    def _generate_report(self, state: Dict) -> Dict:
        """Generate final RCA report with structured output"""
        drift_event: DriftEvent = state["drift_event"]
        analysis = state["analysis"]
        blast_radius = state["blast_radius"]

        risk_assessment = analysis.get("risk_assessment", {})
        risk_score = risk_assessment.get("overall_risk_score", 0.5)

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
        result = self.graph.invoke({"drift_event": drift_event})
        return result["rca_report"]
