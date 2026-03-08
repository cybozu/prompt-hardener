"""Scenario catalog loader, validator, and filter API."""

import json
from pathlib import Path
from typing import List, Optional

import jsonschema
import yaml

from prompt_hardener.models import Scenario, SuccessCriteria

CATALOG_DIR = Path(__file__).parent
CATALOG_VERSION = "1.0"


def get_builtin_catalog_dir():
    # type: () -> Path
    """Return the path to the built-in scenario catalog directory."""
    return CATALOG_DIR


def _load_scenario_schema():
    # type: () -> dict
    schema_path = Path(__file__).parent.parent / "schemas" / "scenario.schema.json"
    with open(str(schema_path), "r", encoding="utf-8") as f:
        return json.load(f)


def _dict_to_scenario(data):
    # type: (dict) -> Scenario
    sc = data["success_criteria"]
    return Scenario(
        id=data["id"],
        name=data["name"],
        category=data["category"],
        target_layer=data["target_layer"],
        applicability=list(data["applicability"]),
        injection_method=data["injection_method"],
        payloads=list(data["payloads"]),
        success_criteria=SuccessCriteria(
            description=sc["description"],
            indicators=list(sc["indicators"]),
        ),
        description=data.get("description"),
    )


def load_scenario(path):
    # type: (str) -> Scenario
    """Load a single scenario YAML file.

    Raises ValueError on file-not-found, YAML syntax errors, or schema violations.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise ValueError("File not found: %s" % path)

    try:
        with open(str(file_path), "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError("YAML parse error in %s: %s" % (path, e))

    if not isinstance(data, dict):
        raise ValueError("Expected a YAML mapping at top level in %s" % path)

    schema = _load_scenario_schema()
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        messages = []
        for error in errors:
            p = ".".join(str(seg) for seg in error.absolute_path) or "(root)"
            messages.append("at '%s': %s" % (p, error.message))
        raise ValueError(
            "Schema validation failed for %s:\n  %s" % (path, "\n  ".join(messages))
        )

    return _dict_to_scenario(data)


def load_catalog(catalog_dir=None):
    # type: (Optional[str]) -> List[Scenario]
    """Load all scenario YAML files from a directory.

    Uses the built-in catalog directory by default.
    Raises ValueError on duplicate IDs or invalid files.
    """
    if catalog_dir is None:
        dir_path = CATALOG_DIR
    else:
        dir_path = Path(catalog_dir)

    if not dir_path.is_dir():
        raise ValueError("Catalog directory not found: %s" % dir_path)

    yaml_files = sorted(dir_path.glob("*.yaml"))
    if not yaml_files:
        return []

    scenarios = []
    seen_ids = {}  # type: dict[str, str]
    for yaml_file in yaml_files:
        scenario = load_scenario(str(yaml_file))
        if scenario.id in seen_ids:
            raise ValueError(
                "Duplicate scenario ID '%s' in %s (first seen in %s)"
                % (scenario.id, yaml_file.name, seen_ids[scenario.id])
            )
        seen_ids[scenario.id] = yaml_file.name
        scenarios.append(scenario)

    return sorted(scenarios, key=lambda s: s.id)


def filter_scenarios(
    scenarios,
    agent_type=None,
    layers=None,
    categories=None,
    injection_methods=None,
):
    # type: (List[Scenario], Optional[str], Optional[List[str]], Optional[List[str]], Optional[List[str]]) -> List[Scenario]
    """Filter scenarios by criteria. All filters are AND-combined; values within each filter are OR-combined."""
    result = []
    for s in scenarios:
        if agent_type and agent_type not in s.applicability:
            continue
        if layers and s.target_layer not in layers:
            continue
        if categories and s.category not in categories:
            continue
        if injection_methods and s.injection_method not in injection_methods:
            continue
        result.append(s)
    return result
