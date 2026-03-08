"""Diff subcommand: compare two agent_spec.yaml files and show differences."""

import difflib
import json
from dataclasses import dataclass, field
from typing import List, Optional

from prompt_hardener.agent_spec import load_yaml


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class FieldDiff:
    """A single field-level difference."""

    path: str  # e.g., "system_prompt", "tools[0].name"
    change_type: str  # "added" | "removed" | "modified"
    before: Optional[str] = None
    after: Optional[str] = None


@dataclass
class SpecDiff:
    """Complete diff result between two specs."""

    before_path: str
    after_path: str
    before_type: str
    after_type: str
    changes: List[FieldDiff] = field(default_factory=list)
    system_prompt_diff: Optional[str] = None  # unified diff text


# ---------------------------------------------------------------------------
# Comparison logic
# ---------------------------------------------------------------------------

_SCALAR_FIELDS = ["version", "type", "name", "description", "user_input_description"]


def compute_diff(before, after):
    # type: (Dict[str, Any], Dict[str, Any]) -> SpecDiff
    """Compute a semantic diff between two agent spec dicts.

    Compares scalar fields, system_prompt (with unified diff),
    list fields (tools, data_sources, mcp_servers) by name matching,
    and policies sub-fields.
    """
    diff = SpecDiff(
        before_path="",
        after_path="",
        before_type=str(before.get("type", "")),
        after_type=str(after.get("type", "")),
    )

    # Scalar fields
    for f in _SCALAR_FIELDS:
        b_val = before.get(f)
        a_val = after.get(f)
        if b_val == a_val:
            continue
        if b_val is None:
            diff.changes.append(
                FieldDiff(path=f, change_type="added", after=str(a_val))
            )
        elif a_val is None:
            diff.changes.append(
                FieldDiff(path=f, change_type="removed", before=str(b_val))
            )
        else:
            diff.changes.append(
                FieldDiff(
                    path=f, change_type="modified", before=str(b_val), after=str(a_val)
                )
            )

    # System prompt: unified diff
    b_prompt = before.get("system_prompt", "")
    a_prompt = after.get("system_prompt", "")
    if b_prompt != a_prompt:
        diff.changes.append(
            FieldDiff(
                path="system_prompt",
                change_type="modified",
                before=str(b_prompt),
                after=str(a_prompt),
            )
        )
        b_lines = str(b_prompt).splitlines(keepends=True)
        a_lines = str(a_prompt).splitlines(keepends=True)
        unified = list(
            difflib.unified_diff(
                b_lines,
                a_lines,
                fromfile="before/system_prompt",
                tofile="after/system_prompt",
            )
        )
        if unified:
            diff.system_prompt_diff = "".join(unified)

    # Named list fields: tools, data_sources, mcp_servers
    for list_field in ["tools", "data_sources", "mcp_servers"]:
        _compare_named_list(diff, before, after, list_field)

    # Policies
    _compare_policies(diff, before, after)

    # Provider
    _compare_provider(diff, before, after)

    return diff


def _compare_named_list(diff, before, after, field_name):
    # type: (SpecDiff, Dict, Dict, str) -> None
    """Compare a list of dicts that have a 'name' key."""
    b_items = before.get(field_name) or []
    a_items = after.get(field_name) or []

    b_by_name = {
        item.get("name", ""): item for item in b_items if isinstance(item, dict)
    }
    a_by_name = {
        item.get("name", ""): item for item in a_items if isinstance(item, dict)
    }

    all_names = list(dict.fromkeys(list(b_by_name.keys()) + list(a_by_name.keys())))

    for name in all_names:
        path = "%s[%s]" % (field_name, name)
        if name not in b_by_name:
            diff.changes.append(
                FieldDiff(
                    path=path,
                    change_type="added",
                    after=json.dumps(a_by_name[name], ensure_ascii=False),
                )
            )
        elif name not in a_by_name:
            diff.changes.append(
                FieldDiff(
                    path=path,
                    change_type="removed",
                    before=json.dumps(b_by_name[name], ensure_ascii=False),
                )
            )
        else:
            b_item = b_by_name[name]
            a_item = a_by_name[name]
            if b_item != a_item:
                diff.changes.append(
                    FieldDiff(
                        path=path,
                        change_type="modified",
                        before=json.dumps(b_item, ensure_ascii=False),
                        after=json.dumps(a_item, ensure_ascii=False),
                    )
                )


def _compare_policies(diff, before, after):
    # type: (SpecDiff, Dict, Dict) -> None
    """Compare policies sub-fields."""
    b_pol = before.get("policies") or {}
    a_pol = after.get("policies") or {}

    if b_pol == a_pol:
        return

    for sub_field in [
        "allowed_actions",
        "denied_actions",
        "data_boundaries",
        "escalation_rules",
    ]:
        path = "policies.%s" % sub_field
        b_val = b_pol.get(sub_field)
        a_val = a_pol.get(sub_field)
        if b_val == a_val:
            continue
        if b_val is None:
            diff.changes.append(
                FieldDiff(
                    path=path,
                    change_type="added",
                    after=json.dumps(a_val, ensure_ascii=False),
                )
            )
        elif a_val is None:
            diff.changes.append(
                FieldDiff(
                    path=path,
                    change_type="removed",
                    before=json.dumps(b_val, ensure_ascii=False),
                )
            )
        else:
            diff.changes.append(
                FieldDiff(
                    path=path,
                    change_type="modified",
                    before=json.dumps(b_val, ensure_ascii=False),
                    after=json.dumps(a_val, ensure_ascii=False),
                )
            )


def _compare_provider(diff, before, after):
    # type: (SpecDiff, Dict, Dict) -> None
    """Compare provider section."""
    b_prov = before.get("provider") or {}
    a_prov = after.get("provider") or {}

    if b_prov == a_prov:
        return

    for sub_field in ["api", "model", "region", "profile"]:
        path = "provider.%s" % sub_field
        b_val = b_prov.get(sub_field)
        a_val = a_prov.get(sub_field)
        if b_val == a_val:
            continue
        if b_val is None:
            diff.changes.append(
                FieldDiff(path=path, change_type="added", after=str(a_val))
            )
        elif a_val is None:
            diff.changes.append(
                FieldDiff(path=path, change_type="removed", before=str(b_val))
            )
        else:
            diff.changes.append(
                FieldDiff(
                    path=path,
                    change_type="modified",
                    before=str(b_val),
                    after=str(a_val),
                )
            )


# ---------------------------------------------------------------------------
# Text renderer (ANSI colors)
# ---------------------------------------------------------------------------

_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def render_text_diff(diff):
    # type: (SpecDiff) -> str
    """Render diff as ANSI-colored text for terminal output."""
    lines = []

    lines.append("%s--- %s%s" % (_BOLD, diff.before_path or "before", _RESET))
    lines.append("%s+++ %s%s" % (_BOLD, diff.after_path or "after", _RESET))
    lines.append("")

    if diff.before_type != diff.after_type:
        lines.append(
            "%sType changed: %s -> %s%s"
            % (_YELLOW, diff.before_type, diff.after_type, _RESET)
        )
        lines.append("")

    if not diff.changes:
        lines.append("No differences found.")
        return "\n".join(lines)

    # System prompt diff (special rendering)
    if diff.system_prompt_diff:
        lines.append("%s== system_prompt ==%s" % (_CYAN, _RESET))
        for line in diff.system_prompt_diff.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                lines.append("%s%s%s" % (_GREEN, line, _RESET))
            elif line.startswith("-") and not line.startswith("---"):
                lines.append("%s%s%s" % (_RED, line, _RESET))
            else:
                lines.append(line)
        lines.append("")

    # Other changes
    for change in diff.changes:
        if change.path == "system_prompt":
            continue  # already rendered above
        if change.change_type == "added":
            lines.append("%s+ [added] %s%s" % (_GREEN, change.path, _RESET))
            if change.after:
                lines.append("  %s" % change.after)
        elif change.change_type == "removed":
            lines.append("%s- [removed] %s%s" % (_RED, change.path, _RESET))
            if change.before:
                lines.append("  %s" % change.before)
        elif change.change_type == "modified":
            lines.append("%s~ [modified] %s%s" % (_YELLOW, change.path, _RESET))
            if change.before:
                lines.append("  %s- %s%s" % (_RED, change.before, _RESET))
            if change.after:
                lines.append("  %s+ %s%s" % (_GREEN, change.after, _RESET))
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON renderer
# ---------------------------------------------------------------------------


def render_json_diff(diff):
    # type: (SpecDiff) -> str
    """Render diff as JSON."""
    result = {
        "before_path": diff.before_path,
        "after_path": diff.after_path,
        "before_type": diff.before_type,
        "after_type": diff.after_type,
        "changes": [],
    }
    if diff.system_prompt_diff:
        result["system_prompt_diff"] = diff.system_prompt_diff

    for change in diff.changes:
        c = {
            "path": change.path,
            "change_type": change.change_type,
        }
        if change.before is not None:
            c["before"] = change.before
        if change.after is not None:
            c["after"] = change.after
        result["changes"].append(c)

    return json.dumps(result, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------


def render_markdown_diff(diff):
    # type: (SpecDiff) -> str
    """Render diff as Markdown."""
    lines = []
    lines.append("# Agent Spec Diff")
    lines.append("")
    lines.append("| | Path |")
    lines.append("|---|------|")
    lines.append("| Before | `%s` |" % diff.before_path)
    lines.append("| After | `%s` |" % diff.after_path)
    lines.append("")

    if diff.before_type != diff.after_type:
        lines.append("**Type changed:** %s -> %s" % (diff.before_type, diff.after_type))
        lines.append("")

    if not diff.changes:
        lines.append("No differences found.")
        return "\n".join(lines)

    lines.append("## Changes")
    lines.append("")

    # System prompt diff
    if diff.system_prompt_diff:
        lines.append("### system_prompt")
        lines.append("")
        lines.append("```diff")
        lines.append(diff.system_prompt_diff.rstrip())
        lines.append("```")
        lines.append("")

    # Other changes
    lines.append("| Change | Path | Before | After |")
    lines.append("|--------|------|--------|-------|")
    for change in diff.changes:
        if change.path == "system_prompt":
            continue  # already shown above
        before_str = _md_truncate(change.before or "-")
        after_str = _md_truncate(change.after or "-")
        change_icon = {"added": "+", "removed": "-", "modified": "~"}.get(
            change.change_type, "?"
        )
        lines.append(
            "| %s %s | `%s` | %s | %s |"
            % (change_icon, change.change_type, change.path, before_str, after_str)
        )
    lines.append("")

    return "\n".join(lines)


def _md_truncate(text, max_len=60):
    # type: (str, int) -> str
    """Truncate text for markdown table cells, escaping pipe chars."""
    text = text.replace("|", "\\|").replace("\n", " ")
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


# ---------------------------------------------------------------------------
# Renderer dispatch
# ---------------------------------------------------------------------------

_RENDERERS = {
    "text": render_text_diff,
    "json": render_json_diff,
    "markdown": render_markdown_diff,
}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def run_diff(before_path, after_path, output_format="text"):
    # type: (str, str, str) -> str
    """Load two agent_spec.yaml files, compute diff, and render in requested format.

    Returns the rendered output string.
    """
    before = load_yaml(before_path)
    after = load_yaml(after_path)

    diff = compute_diff(before, after)
    diff.before_path = before_path
    diff.after_path = after_path

    renderer = _RENDERERS.get(output_format)
    if renderer is None:
        raise ValueError("Unsupported diff format: '%s'" % output_format)

    return renderer(diff)
