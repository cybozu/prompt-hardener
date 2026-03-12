"""Live provider integration tests for simulate.

These tests are opt-in and intended for local verification only.

Examples:
    PROMPT_HARDENER_LIVE_SIMULATE=1 OPENAI_API_KEY=... \
      pytest tests/test_simulate_live.py -m live -k openai -rs

    PROMPT_HARDENER_LIVE_SIMULATE=1 ANTHROPIC_API_KEY=... \
      pytest tests/test_simulate_live.py -m live -k claude -rs

    PROMPT_HARDENER_LIVE_SIMULATE=1 AWS_PROFILE=default \
      PROMPT_HARDENER_AWS_REGION=ap-northeast-1 \
      pytest tests/test_simulate_live.py -m live -k bedrock -rs
"""

import os
from pathlib import Path

import pytest

from prompt_hardener.simulate import run_simulate

pytestmark = [pytest.mark.live]

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SPEC_PATH = str(FIXTURES_DIR / "agent_spec.yaml")


def _gate_or_skip():
    if os.getenv("PROMPT_HARDENER_LIVE_SIMULATE") != "1":
        pytest.skip("set PROMPT_HARDENER_LIVE_SIMULATE=1 to run live simulate tests")


def _assert_provider_plumbing(report, provider):
    assert report.summary.total > 0
    assert report.metadata["models"]["attack"]["api"] == provider
    assert report.metadata["models"]["judge"]["api"] == provider
    assert any(s.injection_method == "tool_result" for s in report.scenarios)

    errors = [
        scenario
        for scenario in report.scenarios
        if scenario.details
        and (
            "LLM request failed" in scenario.details
            or "invalid_request_error" in scenario.details
            or "Error code: 400" in scenario.details
        )
    ]
    assert not errors, [
        {
            "id": s.id,
            "injection_method": s.injection_method,
            "details": s.details,
        }
        for s in errors
    ]


@pytest.mark.skipif(
    not os.getenv("OPENAI_API_KEY"),
    reason="OPENAI_API_KEY is required for live OpenAI simulate tests",
)
def test_simulate_live_openai():
    _gate_or_skip()
    report = run_simulate(
        spec_path=SPEC_PATH,
        attack_api_mode="openai",
        attack_model=os.getenv("PROMPT_HARDENER_OPENAI_MODEL", "gpt-4o-mini"),
        judge_api_mode="openai",
        judge_model=os.getenv("PROMPT_HARDENER_OPENAI_MODEL", "gpt-4o-mini"),
        categories=["function_call_hijacking"],
    )
    _assert_provider_plumbing(report, "openai")


@pytest.mark.skipif(
    not os.getenv("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY is required for live Claude simulate tests",
)
def test_simulate_live_claude():
    _gate_or_skip()
    report = run_simulate(
        spec_path=SPEC_PATH,
        attack_api_mode="claude",
        attack_model=os.getenv(
            "PROMPT_HARDENER_CLAUDE_MODEL", "claude-sonnet-4-20250514"
        ),
        judge_api_mode="claude",
        judge_model=os.getenv(
            "PROMPT_HARDENER_CLAUDE_MODEL", "claude-sonnet-4-20250514"
        ),
        categories=["function_call_hijacking"],
    )
    _assert_provider_plumbing(report, "claude")


@pytest.mark.skipif(
    not (
        os.getenv("AWS_PROFILE")
        or os.getenv("AWS_ACCESS_KEY_ID")
        or os.getenv("AWS_DEFAULT_PROFILE")
    ),
    reason="AWS credentials/profile are required for live Bedrock simulate tests",
)
def test_simulate_live_bedrock():
    _gate_or_skip()
    region = os.getenv("PROMPT_HARDENER_AWS_REGION", os.getenv("AWS_REGION", "us-east-1"))
    profile = os.getenv("PROMPT_HARDENER_AWS_PROFILE", os.getenv("AWS_PROFILE"))
    report = run_simulate(
        spec_path=SPEC_PATH,
        attack_api_mode="bedrock",
        attack_model=os.getenv(
            "PROMPT_HARDENER_BEDROCK_MODEL",
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
        ),
        judge_api_mode="bedrock",
        judge_model=os.getenv(
            "PROMPT_HARDENER_BEDROCK_MODEL",
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
        ),
        categories=["function_call_hijacking"],
        aws_region=region,
        aws_profile=profile,
    )
    _assert_provider_plumbing(report, "bedrock")
