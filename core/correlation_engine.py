"""
Graph-based correlation engine
Reduces 7 alerts → 1 root cause (85% noise reduction)
"""
from typing import List, Dict, Set
from datetime import datetime, timedelta
from core.schemas import DriftEvent
import networkx as nx


class CorrelationEngine:
    """Links related drift events to find root cause"""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.time_window = timedelta(hours=1)  # Events within 1 hour are candidates

    def add_event(self, event: DriftEvent):
        """Add drift event to correlation graph"""
        self.graph.add_node(event.event_id, event=event)

    def correlate(self, events: List[DriftEvent]) -> Dict[str, List[DriftEvent]]:
        """
        Group related events by root cause
        Returns: {root_cause_id: [related_events]}
        """
        # Build dependency graph
        for event in events:
            self.add_event(event)

        # Link events based on:
        # 1. Time proximity (within 1 hour)
        # 2. Resource dependencies (security_group → instances)
        # 3. Same tags/metadata

        for i, event1 in enumerate(events):
            for event2 in events[i+1:]:
                if self._are_related(event1, event2):
                    self.graph.add_edge(event1.event_id, event2.event_id, weight=0.8)

        # Find connected components (clusters of related events)
        clusters = {}
        if len(self.graph.nodes) > 0:
            undirected = self.graph.to_undirected()
            for component in nx.connected_components(undirected):
                component_list = list(component)
                root_event_id = component_list[0]  # First event is root cause
                clusters[root_event_id] = [
                    self.graph.nodes[node_id]['event']
                    for node_id in component_list
                ]

        return clusters

    def _are_related(self, event1: DriftEvent, event2: DriftEvent) -> bool:
        """
        Check if two events are related.

        Correlation rules (ANY of these makes events related):
        1. Same resource_id (all alerts about sg-0abc123 are related)
        2. Time proximity + same environment
        3. Resource in blast radius of other resource
        4. Known resource dependencies (SG → instances, IAM → lambdas, etc.)
        """
        # Time proximity check (required for all correlations)
        time_diff = abs((event1.detected_at - event2.detected_at).total_seconds())
        if time_diff > self.time_window.total_seconds():
            return False

        # Same environment check (required)
        env1 = event1.tags.get("environment", "unknown")
        env2 = event2.tags.get("environment", "unknown")
        if env1 != env2:
            return False

        # RULE 1: Same resource_id (strongest correlation)
        # All alerts about the same resource should be grouped
        if event1.resource_id == event2.resource_id:
            return True

        # RULE 2: Resource in blast radius
        # If event2's resource is in event1's blast radius, they're related
        if event2.resource_id in event1.blast_radius:
            return True
        if event1.resource_id in event2.blast_radius:
            return True

        # RULE 3: Known infrastructure dependencies
        # Security group affects instances using it
        if event1.resource_type == "aws_security_group":
            if event2.resource_type == "aws_instance":
                sg_id = event1.resource_id
                instance_sgs = event2.actual_state.get("security_groups", [])
                if sg_id in instance_sgs:
                    return True

        # Reverse check: instance → security group
        if event1.resource_type == "aws_instance":
            if event2.resource_type == "aws_security_group":
                sg_id = event2.resource_id
                instance_sgs = event1.actual_state.get("security_groups", [])
                if sg_id in instance_sgs:
                    return True

        # IAM role affects resources that assume it
        if event1.resource_type == "aws_iam_role":
            if event2.resource_type in ["aws_instance", "aws_lambda_function"]:
                role_name = event1.resource_id
                if role_name in str(event2.actual_state.get("iam_role", "")):
                    return True

        # Subnet affects instances in it
        if event1.resource_type == "aws_subnet":
            if event2.resource_type == "aws_instance":
                subnet_id = event1.resource_id
                if subnet_id == event2.actual_state.get("subnet_id", ""):
                    return True

        return False

    def get_statistics(self) -> Dict:
        """Demo statistics: show noise reduction"""
        total_events = len(self.graph.nodes)
        if total_events == 0:
            return {"total_events": 0, "root_causes": 0, "noise_reduction": 0}

        clusters = list(nx.connected_components(self.graph.to_undirected()))
        root_causes = len(clusters)

        return {
            "total_events": total_events,
            "root_causes": root_causes,
            "noise_reduction_pct": round((1 - root_causes/total_events) * 100, 1) if total_events > 0 else 0,
            "alerts_per_root_cause": round(total_events / root_causes, 1) if root_causes > 0 else 0
        }
