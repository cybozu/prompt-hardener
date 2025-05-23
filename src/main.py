from typing import List, Dict, Any, Optional
import argparse
import json
import os
from evaluate import evaluate_prompt
from improve import improve_prompt
from attack import run_injection_test
from gen_report import generate_report
from utils import validate_chat_completion_format


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate, improve, and test the security of a Chat Completion-style prompt using LLM APIs (OpenAI or Claude)."
    )

    parser.add_argument(
        "-t",
        "--target-prompt-path",
        type=str,
        required=True,
        help="Path to the file containing the target prompt in Chat Completion message format (JSON).",
    )

    parser.add_argument(
        "-ea",
        "--eval-api-mode",
        type=str,
        choices=["openai", "claude", "bedrock"],
        required=True,
        help="LLM API to use for evaluating and improving the prompt (e.g., OpenAI or Claude).",
    )
    parser.add_argument(
        "-em",
        "--eval-model",
        type=str,
        required=True,
        help="Model name for evaluation and improvement (e.g., 'gpt-4o-mini', 'claude-3-7sonnet-latest').",
    )

    parser.add_argument(
        "-aa",
        "--attack-api-mode",
        type=str,
        choices=["openai", "claude", "bedrock"],
        default=None,
        help="LLM API to use for executing attacks. If not provided, defaults to --eval-api-mode.",
    )
    parser.add_argument(
        "-am",
        "--attack-model",
        type=str,
        default=None,
        help="Model to use for executing attacks. If not provided, defaults to --eval-model.",
    )

    parser.add_argument(
        "-ja",
        "--judge-api-mode",
        type=str,
        choices=["openai", "claude", "bedrock"],
        default=None,
        help="LLM API to use for inserting attack payloads and judging success. If not provided, defaults to --eval-api-mode.",
    )
    parser.add_argument(
        "-jm",
        "--judge-model",
        type=str,
        default=None,
        help="Model to use for inserting attack payloads and judging success. If not provided, defaults to --eval-model.",
    )

    parser.add_argument(
        "-ar",
        "--aws-region",
        type=str,
        default="us-east-1",
        help="AWS region for Bedrock API mode. Default is 'us-east-1'.",
    )

    parser.add_argument(
        "-ui",
        "--user-input-description",
        type=str,
        help="Description of user input fields. Helps prevent incorrect placement inside secure instruction tags.",
    )

    parser.add_argument(
        "-o",
        "--output-path",
        type=str,
        required=True,
        help="File path to write the improved prompt as JSON.",
    )

    parser.add_argument(
        "-n",
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum number of self-refinement iterations. Default is 3.",
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=8.5,
        help="Score threshold (0-10) to stop refinement. If reached, iteration halts early. Default is 8.5.",
    )

    parser.add_argument(
        "-a",
        "--apply-techniques",
        nargs="+",
        choices=[
            "spotlighting",
            "signed_prompt",
            "rule_reinforcement",
            "structured_output",
        ],
        help="List of techniques to apply during prompt improvement. Defaults to all if not specified.",
    )

    parser.add_argument(
        "-ta",
        "--test-after",
        action="store_true",
        help="Run prompt injection test automatically after refinement.",
    )

    parser.add_argument(
        "-ts",
        "--test-separator",
        type=str,
        default=None,
        help="Optional string to prepend to each attack payload (e.g., '\\n').",
    )

    parser.add_argument(
        "-tp",
        "--tools-path",
        type=str,
        help="Path to a JSON file that defines available tools/functions for the LLM (used during attack).",
    )

    parser.add_argument(
        "-rd",
        "--report-dir",
        type=str,
        help="Directory to write a full HTML and JSON report after execution.",
    )

    return parser.parse_args()


def load_target_prompt(file_path: str) -> List[Dict[str, str]]:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_to_file(output_path: str, content: List[Dict[str, str]]) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(content, f, indent=2, ensure_ascii=False)
    print(f"Improved prompt written to: {output_path}")


def load_tools(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[Error] Failed to load tools JSON: {e}")
        return None


def average_satisfaction(evaluation: Dict[str, Any]) -> float:
    total, count = 0, 0
    for category, items in evaluation.items():
        if category in ("critique", "recommendation"):
            continue
        for sub in items.values():
            try:
                total += float(sub["satisfaction"])
                count += 1
            except (ValueError, TypeError):
                continue
    return round((total / count), 2) if count else 0.0


def main() -> None:
    args = parse_args()
    current_prompt = load_target_prompt(args.target_prompt_path)
    print(
        f"Loaded target prompt from {args.target_prompt_path}:\n{json.dumps(current_prompt, indent=2, ensure_ascii=False)}"
    )
    try:
        validate_chat_completion_format(current_prompt)
    except ValueError as e:
        print(f"[Error] Invalid Chat Completion format: {e}")
        return

    if args.attack_api_mode is None:
        args.attack_api_mode = args.eval_api_mode
    if args.attack_model is None:
        args.attack_model = args.eval_model
    if args.judge_api_mode is None:
        args.judge_api_mode = args.eval_api_mode
    if args.judge_model is None:
        args.judge_model = args.eval_model

    initial_prompt = current_prompt
    apply_techniques = args.apply_techniques or [
        "spotlighting",
        "signed_prompt",
        "rule_reinforcement",
        "structured_output",
    ]

    initial_evaluation = evaluate_prompt(
        args.eval_api_mode, args.eval_model, initial_prompt, args.user_input_description
    )
    initial_avg_score = average_satisfaction(initial_evaluation)
    print("Initial Evaluation Result:")
    print(initial_evaluation)
    print(f"Initial Average Satisfaction Score: {initial_avg_score:.2f}")

    evaluation_result = initial_evaluation
    final_avg_score = initial_avg_score

    for i in range(args.max_iterations):
        print(f"\n--- Iteration {i + 1} ---")
        if i > 0:
            evaluation_result = evaluate_prompt(
                args.eval_api_mode,
                args.eval_model,
                current_prompt,
                args.user_input_description,
                aws_region=args.aws_region,
            )
            print("Evaluation Result:")
            print(evaluation_result)

            final_avg_score = average_satisfaction(evaluation_result)
            print(f"Average Satisfaction Score: {final_avg_score:.2f}")

            if final_avg_score >= args.threshold:
                print(
                    "Prompt meets the required security threshold. Stopping refinement."
                )
                break

        current_prompt = improve_prompt(
            args.eval_api_mode,
            args.eval_model,
            args.attack_api_mode,
            current_prompt,
            evaluation_result,
            args.user_input_description,
            apply_techniques=apply_techniques,
            aws_region=args.aws_region,
        )
        print("Improved Prompt:")
        print(json.dumps(current_prompt, indent=2, ensure_ascii=False))

    if args.max_iterations == 1 or final_avg_score < args.threshold:
        print("\n--- Final Evaluation ---")
        evaluation_result = evaluate_prompt(
            args.eval_api_mode,
            args.eval_model,
            current_prompt,
            args.user_input_description,
        )
        print("Final Evaluation Result:")
        print(evaluation_result)
        final_avg_score = average_satisfaction(evaluation_result)
        print(f"Average Satisfaction Score: {final_avg_score:.2f}")

    write_to_file(args.output_path, current_prompt)

    attack_results = []
    if args.test_after:
        tools = load_tools(args.tools_path) if args.tools_path else None
        print("\n--- Running injection test on final prompt ---")
        attack_results = run_injection_test(
            current_prompt,
            args.attack_api_mode,
            args.attack_model,
            args.judge_api_mode,
            args.judge_model,
            apply_techniques,
            args.test_separator,
            tools,
        )

    if args.report_dir:
        report_dir_path = os.path.abspath(args.report_dir)
        print(f"\n--- Generating report at {report_dir_path} ---")
        generate_report(
            initial_prompt,
            initial_evaluation,
            current_prompt,
            evaluation_result,
            attack_results,
            report_dir_path,
            initial_avg_score,
            final_avg_score,
            args.eval_model,
            args.attack_model,
            args.judge_model,
            args.eval_api_mode,
            args.attack_api_mode,
            args.judge_api_mode,
        )
        print("Report generation complete.")


if __name__ == "__main__":
    main()
