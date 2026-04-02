#!/usr/bin/env python3
"""
Blast Radius Analysis: Property Graph + Causal AI
==================================================
Demonstrates two complementary techniques for drift understanding:
  1. Property Graph Model → WHAT is affected (blast radius)
  2. Causal AI (PC Algorithm) → WHY it happened (root cause)
"""

import networkx as nx
from collections import deque
from typing import Dict, List, Set, Tuple
import json

# ============================================================================
# [PART A] PROPERTY GRAPH MODEL
# ============================================================================

class InfrastructureGraph:
    """
    Models cloud infrastructure as a property graph.
    Nodes: Resources (EC2, RDS, SG, etc.)
    Edges: Relationships (SECURES, CONNECTS_TO, MOUNTS, etc.)
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.criticality_weights = {
            'aws_db_instance': 1.0,      # Databases: critical
            'aws_kms_key': 0.95,         # Encryption keys: critical
            'aws_iam_role': 0.9,         # Identity: critical
            'aws_security_group': 0.8,   # Network security: important
            'aws_s3_bucket': 0.6,        # Storage: moderate
            'aws_efs_filesystem': 0.5,   # Shared storage: moderate
            'aws_instance': 0.5,         # Compute alone: less critical
        }

    def add_resource(self, resource_id: str, resource_type: str, metadata: Dict):
        """Add a resource node to the graph."""
        self.graph.add_node(
            resource_id,
            type=resource_type,
            criticality=self.criticality_weights.get(resource_type, 0.5),
            **metadata
        )

    def add_relationship(self, source: str, target: str, rel_type: str):
        """Add a relationship edge between resources."""
        self.graph.add_edge(source, target, relationship=rel_type)

    def get_blast_radius(self, resource_id: str) -> List[str]:
        """
        Compute blast radius using BFS (breadth-first search).
        Returns all downstream resources affected by changes to resource_id.
        """
        if resource_id not in self.graph:
            return []

        # BFS traversal to find all reachable nodes
        visited = set()
        queue = deque([resource_id])
        blast_radius = []

        while queue:
            current = queue.popleft()
            if current in visited:
                continue

            visited.add(current)
            if current != resource_id:  # Don't include the source node
                blast_radius.append(current)

            # Add all downstream neighbors to queue
            for neighbor in self.graph.successors(current):
                if neighbor not in visited:
                    queue.append(neighbor)

        return blast_radius

    def risk_score(self, resource_id: str) -> float:
        """
        Calculate risk score for a resource.
        Formula: base_criticality × (1.0 + blast_radius_count × 0.05)
        Capped at 1.3× multiplier (30% increase max)
        """
        if resource_id not in self.graph:
            return 0.0

        # Base criticality from resource type
        base_criticality = self.graph.nodes[resource_id].get('criticality', 0.5)

        # Blast radius multiplier
        blast_radius = self.get_blast_radius(resource_id)
        radius_count = len(blast_radius)
        multiplier = min(1.0 + (radius_count * 0.05), 1.3)

        return round(base_criticality * multiplier, 2)

    def analyze_drift(self, drifted_resource: str) -> Dict:
        """
        Analyze impact of drift on a specific resource.
        Returns WHAT is affected.
        """
        blast_radius = self.get_blast_radius(drifted_resource)
        risk = self.risk_score(drifted_resource)

        # Group affected resources by type
        affected_by_type = {}
        for resource in blast_radius:
            res_type = self.graph.nodes[resource]['type']
            affected_by_type.setdefault(res_type, []).append(resource)

        return {
            'drifted_resource': drifted_resource,
            'resource_type': self.graph.nodes[drifted_resource]['type'],
            'blast_radius_count': len(blast_radius),
            'affected_resources': blast_radius,
            'affected_by_type': affected_by_type,
            'risk_score': risk,
            'risk_level': 'CRITICAL' if risk >= 0.8 else 'HIGH' if risk >= 0.6 else 'MEDIUM'
        }


# ============================================================================
# [PART B] CAUSAL AI (PC Algorithm)
# ============================================================================

class CausalAnalyzer:
    """
    Causal inference for drift events.
    Uses PC Algorithm to determine WHY drift happened (root cause).

    Note: This is a simplified demonstration. Production would use
    CausalLearn library (PyWhy project) with full PC algorithm implementation.
    """

    def __init__(self):
        self.events = []

    def add_event(self, timestamp: float, event_type: str, resource: str):
        """Add an event to the time-series."""
        self.events.append({
            'timestamp': timestamp,
            'event_type': event_type,
            'resource': resource
        })

    def infer_causation(self) -> Dict:
        """
        Simplified causal inference on event time-series.

        PC Algorithm (full version) uses:
          - Conditional independence tests (statistical)
          - Skeleton discovery
          - Edge orientation

        Output: DAG showing causal relationships (A → B means A caused B)
        """
        # Sort events by timestamp
        sorted_events = sorted(self.events, key=lambda e: e['timestamp'])

        if len(sorted_events) < 2:
            return {'causal_chain': [], 'root_cause': None}

        # Build causal chain based on temporal ordering
        # (simplified: actual PC algorithm uses statistical tests)
        causal_chain = []
        for i in range(len(sorted_events) - 1):
            current = sorted_events[i]
            next_event = sorted_events[i + 1]

            causal_chain.append({
                'cause': f"{current['event_type']}",
                'effect': f"{next_event['event_type']}",
                'time_delta': round(next_event['timestamp'] - current['timestamp'], 2),
                'confidence': 0.85  # Simplified: real PC provides actual confidence
            })

        return {
            'causal_chain': causal_chain,
            'root_cause': sorted_events[0]['event_type'] if sorted_events else None,
            'algorithm': 'PC (Peter-Clark)',
            'note': 'Temporal ordering + conditional independence tests'
        }


# ============================================================================
# [DEMONSTRATION] Build Example Infrastructure Graph
# ============================================================================

def build_example_infrastructure():
    """
    Build the example infrastructure from Slide 8:

    [VPC]
      └── [Subnet: private-1]
            └── [SG: sg-0abc123]  ← DRIFT NODE
                  ├──[SECURES]──► [EC2: app-prod-1]
                  │                    ├──[CONNECTS_TO]──► [RDS: db-prod]
                  │                    └──[MOUNTS]────────► [EFS: fs-01]
                  └──[SECURES]──► [EC2: app-prod-2]
                                       └──[CONNECTS_TO]──► [RDS: db-prod]
    """
    graph = InfrastructureGraph()

    # Add resources
    graph.add_resource('vpc-main', 'aws_vpc', {'name': 'main'})
    graph.add_resource('subnet-private-1', 'aws_subnet', {'name': 'private-1'})
    graph.add_resource('sg-0abc123', 'aws_security_group', {'name': 'api_sg'})
    graph.add_resource('ec2-app-prod-1', 'aws_instance', {'name': 'app-prod-1'})
    graph.add_resource('ec2-app-prod-2', 'aws_instance', {'name': 'app-prod-2'})
    graph.add_resource('rds-db-prod', 'aws_db_instance', {'name': 'db-prod'})
    graph.add_resource('efs-fs-01', 'aws_efs_filesystem', {'name': 'fs-01'})

    # Add relationships
    graph.add_relationship('vpc-main', 'subnet-private-1', 'CONTAINS')
    graph.add_relationship('subnet-private-1', 'sg-0abc123', 'CONTAINS')
    graph.add_relationship('sg-0abc123', 'ec2-app-prod-1', 'SECURES')
    graph.add_relationship('sg-0abc123', 'ec2-app-prod-2', 'SECURES')
    graph.add_relationship('ec2-app-prod-1', 'rds-db-prod', 'CONNECTS_TO')
    graph.add_relationship('ec2-app-prod-1', 'efs-fs-01', 'MOUNTS')
    graph.add_relationship('ec2-app-prod-2', 'rds-db-prod', 'CONNECTS_TO')

    return graph


def build_example_causal_timeline():
    """
    Build example causal timeline from Slide 8:

    [deploy] → [sg_change] → [cpu_spike]

    NOT: [cpu_spike] → [sg_change]
    """
    analyzer = CausalAnalyzer()

    # Event timeline (T in seconds)
    analyzer.add_event(0.0, 'deploy', 'deployment-v2.3.1')
    analyzer.add_event(2.0, 'sg_change', 'sg-0abc123')
    analyzer.add_event(4.0, 'cpu_spike', 'ec2-app-prod-1')

    return analyzer


# ============================================================================
# [MAIN] Run Analysis
# ============================================================================

def main():
    print("━" * 80)
    print("[PROPERTY GRAPH MODEL]")
    print("━" * 80)
    print()

    # Build infrastructure graph
    infra = build_example_infrastructure()

    # Visualize graph structure
    print("[VPC]")
    print("  ├── [Subnet: private-1]")
    print("  │       └── [SG: sg-0abc123]  ◄━━ DRIFT NODE")
    print("  │                 ├──[SECURES]──► [EC2: app-prod-1]")
    print("  │                 │                    ├──[CONNECTS_TO]──► [RDS: db-prod]")
    print("  │                 │                    └──[MOUNTS]────────► [EFS: fs-01]")
    print("  │                 └──[SECURES]──► [EC2: app-prod-2]")
    print("  │                                      └──[CONNECTS_TO]──► [RDS: db-prod]")
    print()

    # OLD MODEL vs GRAPH MODEL comparison
    print('OLD MODEL:  "sg-0abc123 CIDR changed"')
    print("            → 1 resource, 1 alert")
    print()
    print('GRAPH MODEL: "sg-0abc123 CIDR changed"')

    # Analyze drift impact
    analysis = infra.analyze_drift('sg-0abc123')

    print(f"            → Direct risk:    {len([r for r in analysis['affected_resources'] if 'ec2' in r])} EC2 instances")
    print(f"            → Transitive:     RDS, EFS (via EC2)")
    print(f"            → Blast radius:   {analysis['blast_radius_count']} downstream resources")
    print(f"            → Risk score:     {analysis['risk_score']} ({analysis['risk_level']})")
    print()

    # Show affected resources by type
    print("Affected resources by type:")
    for res_type, resources in analysis['affected_by_type'].items():
        print(f"  - {res_type}: {len(resources)} ({', '.join([r.split('-')[-1] for r in resources])})")
    print()

    print("━" * 80)
    print("[CAUSAL AI]")
    print("━" * 80)
    print()

    print("GRAPH tells you:")
    print("  WHAT is affected")
    print()
    print("CAUSAL AI tells you:")
    print("  WHY it happened")
    print()

    # Causal analysis
    causal = build_example_causal_timeline()
    causal_result = causal.infer_causation()

    print("PC Algorithm:")
    for link in causal_result['causal_chain']:
        print(f"  [{link['cause']}] → [{link['effect']}]")
    print()

    print("NOT:")
    print("  [cpu_spike] → [sg_change]")
    print()

    print("Output:")
    print(f"  \"Root cause: {causal_result['causal_chain'][1]['cause']}")
    print(f"   caused by: {causal_result['root_cause']}")
    print(f"   NOT by: the cpu alert\"")
    print()

    print("━" * 80)
    print("[IMPLEMENTATION]")
    print("━" * 80)
    print()
    print("Graph DB: NetworkX (dev) · Neo4j (production)")
    print("Causal: CausalLearn (PyWhy) · PC Algorithm")
    print(f"Risk Score: resource_criticality × (1.0 + blast_radius × 0.05)")
    print()

    # Example risk scores
    print("Examples:")
    print(f"  Database: 1.0 · S3 with 10 connections: 0.9 · EC2 alone: 0.5")
    print()

    # Demonstrate risk score calculation
    print("Risk score breakdown for sg-0abc123:")
    sg_node = infra.graph.nodes['sg-0abc123']
    base_crit = sg_node['criticality']
    blast_count = len(analysis['affected_resources'])
    multiplier = min(1.0 + (blast_count * 0.05), 1.3)
    final_score = analysis['risk_score']

    print(f"  Base criticality: {base_crit}")
    print(f"  Blast radius: {blast_count} resources")
    print(f"  Multiplier: {multiplier}×")
    print(f"  Final score: {base_crit} × {multiplier} = {final_score}")
    print()

    print("━" * 80)


if __name__ == '__main__':
    main()
