from unittest.mock import patch

from prompt_hardener.attack import (
    AttackResult,
    execute_single_attack,
    run_injection_test,
)
from prompt_hardener.schema import PromptInput


def test_execute_single_attack_is_legacy_adapter():
    prompt = PromptInput(
        mode="completion",
        completion_prompt="hello",
    )
    fake_result = AttackResult(
        payload="payload",
        response="response",
        success=False,
        outcome="PASSED",
    )

    with patch(
        "prompt_hardener.attack._execute_single_attack", return_value=fake_result
    ) as mock_exec:
        result = execute_single_attack(
            prompt=prompt,
            payload="payload",
            attack_api_mode="openai",
            attack_model="gpt-4o-mini",
            judge_api_mode="openai",
            judge_model="gpt-4o-mini",
        )

    assert result is fake_result
    assert mock_exec.call_count == 1


def test_run_injection_test_preserves_legacy_return_shape():
    prompt = PromptInput(
        mode="completion",
        completion_prompt="hello",
    )
    fake_result = AttackResult(
        payload="payload",
        response="response",
        success=False,
        outcome="PASSED",
    )

    with patch(
        "prompt_hardener.attack.execute_single_attack", return_value=fake_result
    ) as mock_exec:
        results = run_injection_test(
            prompt,
            "openai",
            "gpt-4o-mini",
            "openai",
            "gpt-4o-mini",
        )

    assert len(results) == 39
    assert set(results[0].keys()) == {
        "category",
        "attack",
        "prompt",
        "response",
        "success",
        "result",
    }
    assert mock_exec.call_count == 39
