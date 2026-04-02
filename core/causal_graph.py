"""
Causal Graph Analysis for Drift Detection

Implements causal inference to understand:
- Why did this drift happen?
- What caused what?
- What will happen if we fix this?

Uses PC Algorithm (Peter-Clark) from causal inference literature
combined with domain knowledge for robust causal discovery.

Installation (optional, for PC algorithm):
    pip install causal-learn

If CausalLearn is not available, falls back to heuristic approach
using domain knowledge + temporal ordering (still effective).

References:
- Spirtes, Glymour, Scheines (2000): Causation, Prediction, and Search
- CausalLearn library (PyWhy project): https://causal-learn.readthedocs.io/
- PC Algorithm: Constraint-based causal discovery using conditional independence tests
"""
import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for server environments
import matplotlib.pyplot as plt
import numpy as np
from typing import List, Dict, Tuple, Set, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from core.schemas import DriftEvent

# Try to import CausalLearn for PC algorithm
# If not available, fall back to heuristic approach
try:
    from causallearn.search.ConstraintBased.PC import pc
    from causallearn.utils.cit import chisq, fisherz
    CAUSALLEARN_AVAILABLE = True
except ImportError:
    CAUSALLEARN_AVAILABLE = False
    print("[WARNING] CausalLearn not available. Using heuristic causal inference.")


class CausalGraphAnalyzer:
    """
    Causal Graph Analyzer for Infrastructure Drift

    Purpose:
    - Build causal DAG from drift events
    - Identify root causes using causal inference
    - Predict downstream impact of changes
    - Visualize causal relationships

    Algorithm:
    1. Temporal ordering: Events earlier in time can cause later events
    2. Resource dependencies: Changes to X can cause changes to Y if Y depends on X
    3. Correlation strength: How often do events co-occur?
    4. Causal direction: Use domain knowledge (e.g., SG → instances, not reverse)
    """

    def __init__(self, use_pc_algorithm: bool = True):
        """
        Initialize causal graph analyzer

        Args:
            use_pc_algorithm: If True and CausalLearn available, use PC algorithm
                            for causal discovery. Otherwise use heuristic approach.
        """
        # Directed Acyclic Graph (DAG) for causal relationships
        self.causal_dag = nx.DiGraph()

        # Whether to use PC algorithm (if available)
        self.use_pc_algorithm = use_pc_algorithm and CAUSALLEARN_AVAILABLE

        # Domain knowledge: Known causal relationships in infrastructure
        # Format: (cause_resource_type, effect_resource_type, relationship_strength)
        # Used to augment PC algorithm results with domain expertise
        self.known_causal_edges = [
            ("aws_security_group", "aws_instance", 0.9),       # SG changes affect instances
            ("aws_security_group", "aws_lb", 0.85),            # SG changes affect load balancers
            ("aws_iam_role", "aws_instance", 0.8),             # IAM role changes affect instances
            ("aws_iam_role", "aws_lambda_function", 0.9),      # IAM role changes affect lambdas
            ("aws_vpc", "aws_subnet", 0.95),                   # VPC changes affect subnets
            ("aws_subnet", "aws_instance", 0.9),               # Subnet changes affect instances
            ("aws_route_table", "aws_subnet", 0.85),           # Route table changes affect subnets
            ("aws_kms_key", "aws_s3_bucket", 0.8),             # KMS key changes affect S3
        ]

        # Event data for time-series causal analysis
        self.event_timeseries = []

    def build_causal_graph(self, events: List[DriftEvent]) -> nx.DiGraph:
        """
        Build causal directed acyclic graph from drift events

        Two approaches:
        1. PC Algorithm (if CausalLearn available): Statistical causal discovery
           - Uses conditional independence tests
           - Discovers causal structure from time-series data
           - Mathematically rigorous (Spirtes et al.)

        2. Heuristic Approach (fallback): Domain knowledge + temporal ordering
           - Uses known infrastructure dependencies
           - Temporal precedence (earlier events cause later ones)
           - Good performance without external dependencies

        Args:
            events: List of drift events to analyze

        Returns:
            NetworkX DiGraph with causal edges
        """
        # Clear previous graph
        self.causal_dag.clear()
        self.event_timeseries = events

        if len(events) == 0:
            return self.causal_dag

        # Step 1: Add all events as nodes
        for event in events:
            node_id = event.event_id
            self.causal_dag.add_node(
                node_id,
                event=event,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                timestamp=event.detected_at,
                severity=event.severity,
                environment=event.tags.get("environment", "unknown")
            )

        # Step 2: Build causal edges
        if self.use_pc_algorithm and len(events) >= 3:
            # Use PC Algorithm for causal discovery
            self._build_with_pc_algorithm(events)
        else:
            # Use heuristic approach (domain knowledge + temporal ordering)
            self._build_with_heuristics(events)

        # Step 3: Verify DAG property (no cycles)
        if not nx.is_directed_acyclic_graph(self.causal_dag):
            # Remove edges that create cycles (keep strongest edges)
            self._remove_cycles()

        return self.causal_dag

    def _build_with_pc_algorithm(self, events: List[DriftEvent]):
        """
        Build causal graph using PC Algorithm (Peter-Clark)

        PC Algorithm steps:
        1. Start with fully connected undirected graph
        2. Remove edges using conditional independence tests
        3. Orient edges using v-structures and propagation rules
        4. Result: CPDAG (partially directed causal graph)

        Args:
            events: List of drift events
        """
        try:
            # Prepare time-series data matrix for PC algorithm
            # Rows: time points, Columns: event types
            data_matrix, event_types, event_map = self._prepare_timeseries_matrix(events)

            if data_matrix is None or len(data_matrix) < 3:
                # Not enough data for PC algorithm, fall back to heuristics
                self._build_with_heuristics(events)
                return

            # Run PC algorithm
            # alpha: significance level for conditional independence tests (0.05 = 95% confidence)
            cg = pc(
                data_matrix,
                alpha=0.05,
                indep_test=fisherz if data_matrix.dtype == float else chisq,
                stable=True,
                show_progress=False
            )

            # Extract causal edges from PC algorithm result
            causal_matrix = cg.G.graph  # Adjacency matrix

            # Convert PC algorithm results to our causal DAG
            for i in range(len(event_types)):
                for j in range(len(event_types)):
                    if i != j and causal_matrix[i, j] != 0:
                        # Edge exists in PC algorithm result
                        cause_type = event_types[i]
                        effect_type = event_types[j]

                        # Find actual event pairs with this causal relationship
                        cause_events = [e for e in events if e.resource_type == cause_type]
                        effect_events = [e for e in events if e.resource_type == effect_type]

                        # Add edges with temporal constraints
                        for cause_event in cause_events:
                            for effect_event in effect_events:
                                if cause_event.detected_at < effect_event.detected_at:
                                    time_diff = effect_event.detected_at - cause_event.detected_at
                                    if time_diff < timedelta(hours=1):
                                        # Strength from PC algorithm + domain knowledge
                                        pc_strength = 0.8  # PC algorithm confidence
                                        domain_strength = self._get_causal_strength(
                                            cause_event.resource_type,
                                            effect_event.resource_type
                                        )
                                        combined_strength = max(pc_strength, domain_strength)

                                        self.causal_dag.add_edge(
                                            cause_event.event_id,
                                            effect_event.event_id,
                                            weight=combined_strength,
                                            time_diff=time_diff.total_seconds(),
                                            causal_type="pc_algorithm",
                                            pc_discovered=True
                                        )

        except Exception as e:
            print(f"[WARNING] PC algorithm failed: {e}. Falling back to heuristics.")
            self._build_with_heuristics(events)

    def _prepare_timeseries_matrix(self, events: List[DriftEvent]) -> Tuple[Optional[np.ndarray], List[str], Dict]:
        """
        Prepare time-series data matrix for PC algorithm

        Converts discrete events into continuous time-series:
        - Each row: time window (e.g., 5-minute intervals)
        - Each column: event type (resource type)
        - Values: count of events in that window

        Args:
            events: List of drift events

        Returns:
            Tuple of (data_matrix, event_types, event_map)
        """
        if len(events) == 0:
            return None, [], {}

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.detected_at)

        # Get time range
        start_time = sorted_events[0].detected_at
        end_time = sorted_events[-1].detected_at
        duration = (end_time - start_time).total_seconds()

        if duration < 60:  # Less than 1 minute
            return None, [], {}

        # Create time windows (5-minute intervals)
        window_size = 300  # 5 minutes in seconds
        num_windows = max(3, int(duration / window_size) + 1)

        # Get unique event types
        event_types = sorted(list(set(e.resource_type for e in events)))
        event_type_idx = {et: i for i, et in enumerate(event_types)}

        # Initialize data matrix
        data_matrix = np.zeros((num_windows, len(event_types)))

        # Fill matrix with event counts
        for event in sorted_events:
            time_offset = (event.detected_at - start_time).total_seconds()
            window_idx = min(int(time_offset / window_size), num_windows - 1)
            type_idx = event_type_idx[event.resource_type]
            data_matrix[window_idx, type_idx] += 1

        return data_matrix, event_types, event_type_idx

    def _build_with_heuristics(self, events: List[DriftEvent]):
        """
        Build causal graph using heuristic approach

        Combines:
        1. Temporal ordering (earlier events cause later events)
        2. Domain knowledge (known infrastructure dependencies)
        3. Time proximity (events close in time are more likely causal)

        Args:
            events: List of drift events
        """
        sorted_events = sorted(events, key=lambda e: e.detected_at)
        time_window = timedelta(hours=1)  # Events within 1 hour can be causally related

        for i, cause_event in enumerate(sorted_events):
            for effect_event in sorted_events[i+1:]:
                # Check temporal proximity
                time_diff = effect_event.detected_at - cause_event.detected_at

                if time_diff < time_window:
                    # Check if resource types have known causal relationship
                    causal_strength = self._get_causal_strength(
                        cause_event.resource_type,
                        effect_event.resource_type
                    )

                    if causal_strength > 0:
                        # Add causal edge
                        self.causal_dag.add_edge(
                            cause_event.event_id,
                            effect_event.event_id,
                            weight=causal_strength,
                            time_diff=time_diff.total_seconds(),
                            causal_type="heuristic",
                            pc_discovered=False
                        )

    def _get_causal_strength(self, cause_type: str, effect_type: str) -> float:
        """
        Get causal strength between two resource types

        Uses domain knowledge of infrastructure dependencies

        Args:
            cause_type: Resource type of potential cause
            effect_type: Resource type of potential effect

        Returns:
            Float between 0.0 (no causal relationship) and 1.0 (strong causality)
        """
        # Check known causal edges
        for cause, effect, strength in self.known_causal_edges:
            if cause == cause_type and effect == effect_type:
                return strength

        # Same resource type (e.g., one instance affecting another)
        if cause_type == effect_type:
            return 0.3

        # No known causal relationship
        return 0.0

    def _remove_cycles(self):
        """
        Remove edges that create cycles in the graph

        Strategy: Keep edges with highest causal strength, remove weaker ones
        """
        try:
            # Find cycles
            cycles = list(nx.simple_cycles(self.causal_dag))

            for cycle in cycles:
                # Find weakest edge in cycle
                min_weight = float('inf')
                edge_to_remove = None

                for i in range(len(cycle)):
                    u = cycle[i]
                    v = cycle[(i + 1) % len(cycle)]

                    if self.causal_dag.has_edge(u, v):
                        weight = self.causal_dag[u][v].get('weight', 0)
                        if weight < min_weight:
                            min_weight = weight
                            edge_to_remove = (u, v)

                # Remove weakest edge to break cycle
                if edge_to_remove:
                    self.causal_dag.remove_edge(*edge_to_remove)
        except:
            pass  # Graph might already be acyclic

    def identify_root_causes(self) -> List[str]:
        """
        Identify root causes using causal graph

        Root causes are nodes with:
        - No incoming edges (nothing caused them)
        - Outgoing edges to other events (they caused other things)

        Returns:
            List of event IDs that are root causes
        """
        root_causes = []

        for node in self.causal_dag.nodes():
            # Check if node has no incoming edges
            in_degree = self.causal_dag.in_degree(node)
            out_degree = self.causal_dag.out_degree(node)

            if in_degree == 0 and out_degree > 0:
                # This is a root cause
                root_causes.append(node)

        return root_causes

    def predict_impact(self, event_id: str) -> Dict:
        """
        Predict downstream impact of an event using causal graph

        Traces all events causally downstream from given event

        Args:
            event_id: Event to analyze impact for

        Returns:
            Dict with:
            - affected_events: List of event IDs affected
            - affected_resources: Set of resource types affected
            - max_depth: Maximum causal depth
            - impact_score: Overall impact score (0.0-1.0)
        """
        if event_id not in self.causal_dag.nodes():
            return {
                "affected_events": [],
                "affected_resources": set(),
                "max_depth": 0,
                "impact_score": 0.0
            }

        # Find all descendants (events causally downstream)
        descendants = nx.descendants(self.causal_dag, event_id)

        # Calculate impact metrics
        affected_resources = set()
        max_depth = 0

        for descendant in descendants:
            node_data = self.causal_dag.nodes[descendant]
            affected_resources.add(node_data['resource_type'])

            # Calculate causal depth (path length from root)
            try:
                path_length = nx.shortest_path_length(self.causal_dag, event_id, descendant)
                max_depth = max(max_depth, path_length)
            except:
                pass

        # Calculate impact score (0.0 to 1.0)
        # Based on: number of affected events, resource diversity, causal depth
        num_affected = len(descendants)
        resource_diversity = len(affected_resources)

        impact_score = min(1.0, (
            (num_affected / 10.0) * 0.4 +      # More affected events = higher impact
            (resource_diversity / 5.0) * 0.3 +  # More resource types = higher impact
            (max_depth / 3.0) * 0.3              # Deeper causal chains = higher impact
        ))

        return {
            "affected_events": list(descendants),
            "affected_resources": affected_resources,
            "max_depth": max_depth,
            "impact_score": impact_score
        }

    def get_causal_explanation(self, event_id: str) -> str:
        """
        Generate human-readable causal explanation

        Args:
            event_id: Event to explain

        Returns:
            String explanation of causal relationships
        """
        if event_id not in self.causal_dag.nodes():
            return "Event not found in causal graph"

        node_data = self.causal_dag.nodes[event_id]
        event = node_data['event']

        # Check if this is a root cause
        in_degree = self.causal_dag.in_degree(event_id)
        out_degree = self.causal_dag.out_degree(event_id)

        if in_degree == 0 and out_degree > 0:
            # Root cause
            descendants = list(nx.descendants(self.causal_dag, event_id))
            return (
                f"ROOT CAUSE: {event.resource_type}.{event.resource_id} "
                f"caused {len(descendants)} downstream event(s)"
            )
        elif in_degree > 0 and out_degree > 0:
            # Intermediate cause
            ancestors = list(nx.ancestors(self.causal_dag, event_id))
            descendants = list(nx.descendants(self.causal_dag, event_id))
            return (
                f"INTERMEDIATE: {event.resource_type}.{event.resource_id} "
                f"was caused by {len(ancestors)} event(s) and caused {len(descendants)} event(s)"
            )
        elif in_degree > 0 and out_degree == 0:
            # Leaf node (effect only)
            ancestors = list(nx.ancestors(self.causal_dag, event_id))
            return (
                f"EFFECT: {event.resource_type}.{event.resource_id} "
                f"was caused by {len(ancestors)} upstream event(s)"
            )
        else:
            # Isolated event
            return f"ISOLATED: {event.resource_type}.{event.resource_id} has no causal relationships"

    def visualize_causal_graph(self, output_path: str = "causal_graph.png"):
        """
        Visualize causal graph using matplotlib

        Creates a directed graph visualization showing:
        - Nodes: Drift events (colored by severity)
        - Edges: Causal relationships (thickness = strength)
        - Layout: Hierarchical (root causes at top)

        Args:
            output_path: Path to save visualization
        """
        if len(self.causal_dag.nodes()) == 0:
            print("[WARNING] No nodes in causal graph to visualize")
            return

        # Create figure
        plt.figure(figsize=(14, 10))

        # Use hierarchical layout (root causes at top)
        try:
            pos = nx.spring_layout(self.causal_dag, k=2, iterations=50)
        except:
            pos = nx.shell_layout(self.causal_dag)

        # Node colors based on severity
        severity_colors = {
            "critical": "#d32f2f",  # Red
            "high": "#f57c00",      # Orange
            "medium": "#fbc02d",    # Yellow
            "low": "#388e3c"        # Green
        }

        node_colors = []
        for node in self.causal_dag.nodes():
            severity = self.causal_dag.nodes[node].get('severity', 'low')
            node_colors.append(severity_colors.get(severity, '#757575'))

        # Draw nodes
        nx.draw_networkx_nodes(
            self.causal_dag,
            pos,
            node_color=node_colors,
            node_size=800,
            alpha=0.9
        )

        # Draw edges with thickness based on causal strength
        edges = self.causal_dag.edges()
        weights = [self.causal_dag[u][v].get('weight', 0.5) * 3 for u, v in edges]

        nx.draw_networkx_edges(
            self.causal_dag,
            pos,
            width=weights,
            alpha=0.6,
            edge_color='#424242',
            arrows=True,
            arrowsize=20,
            arrowstyle='->'
        )

        # Draw labels (resource names)
        labels = {}
        for node in self.causal_dag.nodes():
            resource_name = self.causal_dag.nodes[node].get('resource_name', 'unknown')
            # Truncate long names
            labels[node] = resource_name[:15]

        nx.draw_networkx_labels(
            self.causal_dag,
            pos,
            labels,
            font_size=8,
            font_weight='bold'
        )

        # Add legend
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color, markersize=10, label=severity.capitalize())
            for severity, color in severity_colors.items()
        ]
        plt.legend(handles=legend_elements, loc='upper right', title='Severity')

        plt.title("Causal Graph: Infrastructure Drift Analysis", fontsize=16, fontweight='bold')
        plt.axis('off')
        plt.tight_layout()

        # Save figure
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"[SUCCESS] Causal graph saved to: {output_path}")
        plt.close()

    def get_algorithm_info(self) -> Dict:
        """
        Get information about which causal inference algorithm is being used

        Returns:
            Dict with algorithm information
        """
        return {
            "algorithm": "PC Algorithm (Peter-Clark)" if self.use_pc_algorithm else "Heuristic (Domain Knowledge + Temporal)",
            "library": "CausalLearn (PyWhy)" if CAUSALLEARN_AVAILABLE else "NetworkX",
            "causallearn_available": CAUSALLEARN_AVAILABLE,
            "using_pc": self.use_pc_algorithm,
            "method": "Statistical causal discovery with conditional independence tests" if self.use_pc_algorithm else "Temporal ordering with infrastructure domain knowledge"
        }

    def get_statistics(self) -> Dict:
        """
        Get causal graph statistics

        Returns:
            Dict with graph metrics
        """
        if len(self.causal_dag.nodes()) == 0:
            return {
                "algorithm": self.get_algorithm_info()["algorithm"],
                "total_nodes": 0,
                "total_edges": 0,
                "root_causes": 0,
                "leaf_effects": 0,
                "avg_causal_depth": 0.0,
                "pc_discovered_edges": 0,
                "heuristic_edges": 0
            }

        # Calculate statistics
        root_causes = [n for n in self.causal_dag.nodes() if self.causal_dag.in_degree(n) == 0]
        leaf_effects = [n for n in self.causal_dag.nodes() if self.causal_dag.out_degree(n) == 0]

        # Count edges by discovery method
        pc_edges = sum(1 for u, v, data in self.causal_dag.edges(data=True) if data.get('pc_discovered', False))
        heuristic_edges = sum(1 for u, v, data in self.causal_dag.edges(data=True) if not data.get('pc_discovered', False))

        # Average causal depth (average path length from root causes to leaves)
        depths = []
        for root in root_causes:
            for leaf in leaf_effects:
                try:
                    path_length = nx.shortest_path_length(self.causal_dag, root, leaf)
                    depths.append(path_length)
                except:
                    pass

        avg_depth = sum(depths) / len(depths) if depths else 0.0

        return {
            "algorithm": self.get_algorithm_info()["algorithm"],
            "total_nodes": len(self.causal_dag.nodes()),
            "total_edges": len(self.causal_dag.edges()),
            "root_causes": len(root_causes),
            "leaf_effects": len(leaf_effects),
            "avg_causal_depth": round(avg_depth, 2),
            "is_dag": nx.is_directed_acyclic_graph(self.causal_dag),
            "pc_discovered_edges": pc_edges,
            "heuristic_edges": heuristic_edges
        }
