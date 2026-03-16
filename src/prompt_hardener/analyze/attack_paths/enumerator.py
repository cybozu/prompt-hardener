"""End-to-end attack path enumeration."""

from prompt_hardener.analyze.attack_paths.graph import build_attack_graph
from prompt_hardener.analyze.attack_paths.models import (
    PathNode,
    node_to_dict,
    path_nodes_to_steps,
)
from prompt_hardener.analyze.attack_paths.normalize import normalize_spec
from prompt_hardener.analyze.attack_paths.scoring import score_path
from prompt_hardener.analyze.attack_paths.templates import instantiate_templates
from prompt_hardener.analyze.report import AttackPath


def _findings_by_rule(findings):
    mapping = {}
    for finding in findings:
        mapping.setdefault(finding.rule_id, []).append(finding.id)
    return mapping


def _canonical_key(path):
    chain_names = tuple(node.name for node in path.chain)
    return (
        path.category,
        path.entrypoint.name,
        chain_names,
        path.target.name,
        tuple(sorted(path.impact)),
    )


def _merge_drafts(existing, incoming):
    existing.preconditions = sorted(set(existing.preconditions + incoming.preconditions))
    existing.blockers = sorted(set(existing.blockers + incoming.blockers))
    existing.evidence = sorted(set(existing.evidence + incoming.evidence))
    existing.related_findings = sorted(
        set(existing.related_findings + incoming.related_findings)
    )
    existing.recommended_mitigations = sorted(
        set(existing.recommended_mitigations + incoming.recommended_mitigations)
    )
    existing.metadata["exposures"] = "|".join(
        sorted(
            set(
                filter(
                    None,
                    (existing.metadata.get("exposures", "") + "|" + incoming.metadata.get("exposures", "")).split("|"),
                )
            )
        )
    )
    existing.metadata["missing_controls"] = "|".join(
        sorted(
            set(
                filter(
                    None,
                    (
                        existing.metadata.get("missing_controls", "")
                        + "|"
                        + incoming.metadata.get("missing_controls", "")
                    ).split("|"),
                )
            )
        )
    )
    existing.inferred_hops = min(existing.inferred_hops, incoming.inferred_hops)
    existing.boundary_crossings = max(
        existing.boundary_crossings, incoming.boundary_crossings
    )
    return existing


def _node_kind(node: PathNode) -> str:
    mapping = {
        "entrypoint": "entrypoint",
        "control": "control",
        "capability": "capability",
        "asset": "asset",
        "impact": "impact",
    }
    return mapping.get(node.type, "asset")


def _validate_path(graph, path):
    nodes = [path.entrypoint] + list(path.chain) + [path.target]
    for node in nodes:
        if not graph.has_node(_node_kind(node), node.name):
            return False
    if path.chain:
        first = path.chain[0]
        if not graph.has_edge(
            _node_kind(path.entrypoint), path.entrypoint.name, _node_kind(first), first.name
        ):
            return False
    if len(path.chain) > 1:
        for source, target in zip(path.chain, path.chain[1:]):
            if not graph.has_edge(
                _node_kind(source), source.name, _node_kind(target), target.name
            ):
                return False
    if path.chain:
        last = path.chain[-1]
        if not graph.has_edge(
            _node_kind(last), last.name, _node_kind(path.target), path.target.name
        ):
            return False
    return True


def enumerate_attack_paths(spec, findings):
    # type: (AgentSpec, List[Finding]) -> List[AttackPath]
    surface = normalize_spec(spec)
    graph = build_attack_graph(surface)
    drafts = instantiate_templates(surface, _findings_by_rule(findings))

    deduped = {}
    for draft in drafts:
        if not _validate_path(graph, draft):
            continue
        key = _canonical_key(draft)
        if key in deduped:
            deduped[key] = _merge_drafts(deduped[key], draft)
        else:
            deduped[key] = draft

    scored = [score_path(draft) for draft in deduped.values()]
    scored.sort(key=lambda item: (-item.score, item.title))

    attack_paths = []
    for index, draft in enumerate(scored, 1):
        attack_paths.append(
            AttackPath(
                id="path-%03d" % index,
                title=draft.title,
                category=draft.category,
                severity=draft.severity,
                score=draft.score,
                confidence=draft.confidence,
                entrypoint=node_to_dict(draft.entrypoint),
                chain=[node_to_dict(node) for node in draft.chain],
                target=node_to_dict(draft.target),
                impact=list(draft.impact),
                preconditions=list(draft.preconditions),
                blockers=list(draft.blockers),
                evidence=list(draft.evidence),
                related_findings=list(draft.related_findings),
                recommended_mitigations=list(draft.recommended_mitigations),
                description=draft.description,
                name=draft.title,
                steps=path_nodes_to_steps(draft.entrypoint, draft.chain, draft.target),
            )
        )

    return attack_paths
