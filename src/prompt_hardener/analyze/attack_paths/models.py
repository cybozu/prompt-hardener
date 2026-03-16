"""Internal data models for attack path enumeration."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class PathNode:
    type: str
    name: str


@dataclass
class AttackNode:
    id: str
    kind: str
    name: str
    attrs: Dict[str, str] = field(default_factory=dict)


@dataclass
class AttackEdge:
    source: str
    target: str
    relation: str


@dataclass
class AttackGraph:
    nodes: Dict[str, AttackNode] = field(default_factory=dict)
    edges: List[AttackEdge] = field(default_factory=list)

    def add_node(self, kind: str, name: str, **attrs: str) -> str:
        node_id = "%s:%s" % (kind, name)
        if node_id not in self.nodes:
            self.nodes[node_id] = AttackNode(
                id=node_id,
                kind=kind,
                name=name,
                attrs={k: str(v) for k, v in attrs.items()},
            )
        return node_id

    def add_edge(self, source: str, target: str, relation: str) -> None:
        edge = AttackEdge(source=source, target=target, relation=relation)
        if edge not in self.edges:
            self.edges.append(edge)

    def has_node(self, kind: str, name: str) -> bool:
        return "%s:%s" % (kind, name) in self.nodes

    def has_edge(
        self,
        source_kind: str,
        source_name: str,
        target_kind: str,
        target_name: str,
    ) -> bool:
        source_id = "%s:%s" % (source_kind, source_name)
        target_id = "%s:%s" % (target_kind, target_name)
        for edge in self.edges:
            if edge.source == source_id and edge.target == target_id:
                return True
        return False


@dataclass
class NormalizedTool:
    name: str
    description: str
    effect: str
    impact: str
    execution_identity: str
    source: str
    is_sensitive: bool
    can_egress: bool
    can_modify_state: bool
    has_service_identity: bool
    is_high_impact: bool
    can_read_data: bool
    can_persist_state: bool
    is_dangerous: bool


@dataclass
class NormalizedDataSource:
    name: str
    type: str
    trust_level: str
    sensitivity: str
    is_untrusted: bool
    is_confidential: bool
    is_internal: bool


@dataclass
class NormalizedMcpServer:
    name: str
    trust_level: str
    source: str
    allowed_tools: List[str] = field(default_factory=list)
    is_untrusted: bool = False
    is_third_party: bool = False
    has_tool_restrictions: bool = False


@dataclass
class NormalizedControls:
    has_user_input_distrust: bool
    has_retrieved_content_distrust: bool
    has_tool_output_distrust: bool
    has_tenant_isolation: bool
    has_budget_limits: bool
    has_memory_protection: bool
    data_boundaries_text: str
    prompt_text: str
    escalation_texts: List[str] = field(default_factory=list)
    denied_actions: List[str] = field(default_factory=list)

    def has_escalation_for(self, tool_name: str) -> bool:
        tool_lower = tool_name.lower()
        for text in self.escalation_texts:
            if tool_lower in text:
                return True
            if any(part and part in text for part in tool_lower.split("_")):
                return True
        return False

    def is_denied(self, tool_name: str) -> bool:
        return tool_name.lower() in self.denied_actions


@dataclass
class NormalizedSpec:
    agent_type: str
    tools: List[NormalizedTool]
    data_sources: List[NormalizedDataSource]
    mcp_servers: List[NormalizedMcpServer]
    controls: NormalizedControls
    has_persistent_memory: bool
    scope: str
    has_user_message_entrypoint: bool


@dataclass
class PathDraft:
    category: str
    title: str
    entrypoint: PathNode
    chain: List[PathNode]
    target: PathNode
    impact: List[str]
    description: str
    preconditions: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    recommended_mitigations: List[str] = field(default_factory=list)
    related_findings: List[str] = field(default_factory=list)
    score: int = 0
    severity: str = "low"
    confidence: str = "low"
    inferred_hops: int = 0
    boundary_crossings: int = 0
    metadata: Dict[str, str] = field(default_factory=dict)


def node_to_dict(node: PathNode) -> Dict[str, str]:
    return {"type": node.type, "name": node.name}


def node_to_step_text(node: PathNode) -> str:
    kind = node.type.replace("_", " ")
    return "%s: %s" % (kind, node.name)


def path_nodes_to_steps(entrypoint: PathNode, chain: List[PathNode], target: PathNode) -> List[str]:
    nodes = [entrypoint] + list(chain) + [target]
    return [node_to_step_text(node) for node in nodes]
