"""Tests for the shared prompt improvement loop."""

from unittest.mock import patch


from prompt_hardener.prompt_improvement import ImprovementResult, run_improvement_loop
from prompt_hardener.schema import PromptInput


# =========================================================================
# Helper
# =========================================================================


def _make_prompt(content="Test prompt"):
    return PromptInput(
        mode="chat",
        messages=[{"role": "system", "content": content}],
        messages_format="openai",
    )


# =========================================================================
# Group 1: ImprovementResult
# =========================================================================


class TestImprovementResult:
    def test_basic_construction(self):
        initial = _make_prompt("initial")
        improved = _make_prompt("improved")
        result = ImprovementResult(
            initial_prompt=initial,
            improved_prompt=improved,
            initial_evaluation={"cat": {"sub": {"satisfaction": 5}}},
            final_evaluation={"cat": {"sub": {"satisfaction": 9}}},
            initial_score=5.0,
            final_score=9.0,
            iteration_count=2,
        )
        assert result.initial_score == 5.0
        assert result.final_score == 9.0
        assert result.iteration_count == 2
        assert result.initial_prompt is initial
        assert result.improved_prompt is improved

    def test_field_access(self):
        result = ImprovementResult(
            initial_prompt=_make_prompt(),
            improved_prompt=_make_prompt(),
            initial_evaluation={"a": "b"},
            final_evaluation={"c": "d"},
            initial_score=3.0,
            final_score=8.0,
            iteration_count=1,
        )
        assert result.initial_evaluation == {"a": "b"}
        assert result.final_evaluation == {"c": "d"}


# =========================================================================
# Group 2: run_improvement_loop
# =========================================================================


class TestRunImprovementLoop:
    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_basic_loop(self, mock_eval, mock_improve):
        """Test that the loop runs correct number of iterations when below threshold."""
        mock_eval.return_value = {
            "Spotlighting": {"Tag user inputs": {"satisfaction": 5}},
        }
        mock_improve.return_value = _make_prompt("Improved")

        result = run_improvement_loop(
            prompt_input=_make_prompt("Original"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            attack_api_mode="openai",
            max_iterations=3,
            threshold=8.5,
        )

        assert isinstance(result, ImprovementResult)
        assert result.iteration_count == 3
        assert mock_improve.call_count == 3
        # evaluate: 1 initial + (3-1) in-loop + 1 final = 4
        assert mock_eval.call_count == 4

    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_threshold_reached_early(self, mock_eval, mock_improve):
        """Test that loop stops early when threshold is reached."""
        mock_eval.side_effect = [
            {"Cat": {"sub": {"satisfaction": 5}}},  # initial
            {"Cat": {"sub": {"satisfaction": 9}}},  # iter 2: above threshold
        ]
        mock_improve.return_value = _make_prompt("Improved")

        result = run_improvement_loop(
            prompt_input=_make_prompt("Original"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            attack_api_mode="openai",
            max_iterations=5,
            threshold=8.5,
        )

        assert mock_improve.call_count == 1
        assert mock_eval.call_count == 2
        assert result.final_score == 9.0

    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_single_iteration(self, mock_eval, mock_improve):
        """Test with max_iterations=1: always does final evaluation."""
        mock_eval.side_effect = [
            {"Cat": {"sub": {"satisfaction": 5}}},  # initial
            {"Cat": {"sub": {"satisfaction": 7}}},  # final
        ]
        mock_improve.return_value = _make_prompt("Improved")

        result = run_improvement_loop(
            prompt_input=_make_prompt("Original"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            attack_api_mode="openai",
            max_iterations=1,
            threshold=8.5,
        )

        assert result.iteration_count == 1
        assert mock_improve.call_count == 1
        # initial + final = 2
        assert mock_eval.call_count == 2
        assert result.initial_score == 5.0
        assert result.final_score == 7.0

    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_preserves_initial_prompt(self, mock_eval, mock_improve):
        """Test that initial_prompt is preserved unchanged."""
        initial = _make_prompt("Original")
        improved = _make_prompt("Improved")

        mock_eval.return_value = {"Cat": {"sub": {"satisfaction": 9}}}
        mock_improve.return_value = improved

        result = run_improvement_loop(
            prompt_input=initial,
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            attack_api_mode="openai",
            max_iterations=1,
        )

        assert result.initial_prompt is initial
        assert result.improved_prompt is improved


# =========================================================================
# Group 3: attack_api_mode separation
# =========================================================================


class TestAttackApiMode:
    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_attack_api_mode_passed_to_improve(self, mock_eval, mock_improve):
        """Test that attack_api_mode is correctly passed to improve_prompt."""
        mock_eval.return_value = {"Cat": {"sub": {"satisfaction": 9}}}
        mock_improve.return_value = _make_prompt("Improved")

        run_improvement_loop(
            prompt_input=_make_prompt("Original"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            attack_api_mode="claude",
            max_iterations=1,
        )

        # improve_prompt should receive attack_api_mode="claude"
        call_args = mock_improve.call_args
        assert call_args[0][0] == "openai"  # eval_api_mode
        assert call_args[0][1] == "gpt-4o-mini"  # eval_model
        assert call_args[0][2] == "claude"  # attack_api_mode

    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_eval_api_mode_separate_from_attack(self, mock_eval, mock_improve):
        """Test that eval uses eval_api_mode, not attack_api_mode."""
        mock_eval.return_value = {"Cat": {"sub": {"satisfaction": 9}}}
        mock_improve.return_value = _make_prompt("Improved")

        run_improvement_loop(
            prompt_input=_make_prompt("Original"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            attack_api_mode="bedrock",
            max_iterations=1,
        )

        # evaluate_prompt should use eval_api_mode="openai"
        eval_call = mock_eval.call_args
        assert eval_call[0][0] == "openai"
        assert eval_call[0][1] == "gpt-4o-mini"


# =========================================================================
# Group 4: techniques and user_input_description forwarding
# =========================================================================


class TestParameterForwarding:
    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_techniques_forwarded(self, mock_eval, mock_improve):
        """Test that apply_techniques is passed to both evaluate and improve."""
        mock_eval.return_value = {"Cat": {"sub": {"satisfaction": 9}}}
        mock_improve.return_value = _make_prompt("Improved")

        run_improvement_loop(
            prompt_input=_make_prompt("Original"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            attack_api_mode="openai",
            apply_techniques=["spotlighting", "role_consistency"],
            max_iterations=1,
        )

        eval_kwargs = mock_eval.call_args
        assert eval_kwargs[1]["apply_techniques"] == [
            "spotlighting",
            "role_consistency",
        ]
        improve_kwargs = mock_improve.call_args
        assert improve_kwargs[1]["apply_techniques"] == [
            "spotlighting",
            "role_consistency",
        ]

    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_user_input_description_forwarded(self, mock_eval, mock_improve):
        """Test that user_input_description is passed through."""
        mock_eval.return_value = {"Cat": {"sub": {"satisfaction": 9}}}
        mock_improve.return_value = _make_prompt("Improved")

        run_improvement_loop(
            prompt_input=_make_prompt("Original"),
            eval_api_mode="openai",
            eval_model="gpt-4o-mini",
            attack_api_mode="openai",
            user_input_description="User chat messages",
            max_iterations=1,
        )

        eval_call = mock_eval.call_args
        assert eval_call[0][3] == "User chat messages"

    @patch("prompt_hardener.prompt_improvement.improve_prompt")
    @patch("prompt_hardener.prompt_improvement.evaluate_prompt")
    def test_aws_params_forwarded(self, mock_eval, mock_improve):
        """Test that AWS params are forwarded to both evaluate and improve."""
        mock_eval.return_value = {"Cat": {"sub": {"satisfaction": 9}}}
        mock_improve.return_value = _make_prompt("Improved")

        run_improvement_loop(
            prompt_input=_make_prompt("Original"),
            eval_api_mode="bedrock",
            eval_model="model",
            attack_api_mode="bedrock",
            aws_region="us-west-2",
            aws_profile="myprofile",
            max_iterations=1,
        )

        eval_kwargs = mock_eval.call_args[1]
        assert eval_kwargs["aws_region"] == "us-west-2"
        assert eval_kwargs["aws_profile"] == "myprofile"

        improve_kwargs = mock_improve.call_args[1]
        assert improve_kwargs["aws_region"] == "us-west-2"
        assert improve_kwargs["aws_profile"] == "myprofile"
