from typing import List, Dict, Any, Optional
import argparse
import json
import os
from evaluate import evaluate_prompt
from improve import improve_prompt
from attack import run_injection_test
from gen_report import generate_report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate and improve the security of a chat-style prompt using OpenAI or Ollama API with self-refinement."
    )
    parser.add_argument(
        "-t",
        "--target-prompt-path",
        type=str,
        required=True,
        help="Path to the file containing the target prompt in Chat Completion message format (JSON).",
    )
    parser.add_argument(
        "-am",
        "--api-mode",
        type=str,
        choices=["openai", "ollama"],
        required=True,
        help="API mode.",
    )
    parser.add_argument(
        "-m", "--model", type=str, required=True, help="Model name (e.g., 'gpt-4')."
    )
    parser.add_argument(
        "-ui",
        "--user-input-description",
        type=str,
        help="Description of user input fields.",
    )
    parser.add_argument(
        "-o",
        "--output-path",
        type=str,
        required=True,
        help="File path to write improved prompt.",
    )
    parser.add_argument(
        "-n",
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum refinement iterations.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=8.5,
        help="Score threshold to stop refinement. Range: 0-10. Default: 8.5",
    )
    parser.add_argument(
        "--apply-techniques",
        nargs="+",
        choices=[
            "spotlighting",
            "signed_prompt",
            "rule_reinforcement",
            "structured_output",
        ],
        help="Techniques to apply.",
    )
    parser.add_argument(
        "--test-after", action="store_true", help="Run injection test after refinement."
    )
    parser.add_argument(
        "--test-model",
        type=str,
        default="gpt-3.5-turbo",
        help="Model used for post-test.",
    )
    parser.add_argument(
        "--test-separator",
        type=str,
        default=None,
        help="Prefix separator before payload.",
    )
    parser.add_argument(
        "--tools-path", type=str, help="Path to JSON file defining tool specs."
    )
    parser.add_argument(
        "--report-dir",
        type=str,
        help="Directory to write a report after processing.",
    )
    return parser.parse_args()


def load_target_prompt(file_path: str) -> List[Dict[str, str]]:
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_chat_completion_format(prompt: List[Dict[str, str]]) -> None:
    if not isinstance(prompt, list):
        raise ValueError("Prompt must be a JSON array.")
    for entry in prompt:
        if not isinstance(entry, dict):
            raise ValueError("Each entry must be a JSON object.")
        if "role" not in entry or "content" not in entry:
            raise ValueError("Each message must contain 'role' and 'content' keys.")
        if entry["role"] not in ("system", "user", "assistant"):
            raise ValueError(f"Invalid role: {entry['role']}")
        if not isinstance(entry["content"], str):
            raise ValueError("Message 'content' must be a string.")


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
    try:
        validate_chat_completion_format(current_prompt)
    except ValueError as e:
        print(f"[Error] Invalid Chat Completion format: {e}")
        return
    initial_prompt = current_prompt

    apply_techniques = args.apply_techniques or [
        "spotlighting",
        "signed_prompt",
        "rule_reinforcement",
        "structured_output",
    ]

    initial_evaluation = evaluate_prompt(
        args.api_mode, args.model, initial_prompt, args.user_input_description
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
                args.api_mode, args.model, current_prompt, args.user_input_description
            )
            print("Evaluation Result:")
            print(evaluation_result)

            final_avg_score = average_satisfaction(evaluation_result)
            print(f"Average Satisfaction Score: {final_avg_score:.2f}")

            if final_avg_score >= args.threshold:
                print("Prompt meets the required security threshold. Stopping refinement.")
                break

        current_prompt = improve_prompt(
            args.api_mode,
            args.model,
            current_prompt,
            evaluation_result,
            args.user_input_description,
            apply_techniques=apply_techniques,
        )
        print("Improved Prompt:")
        print(json.dumps(current_prompt, indent=2, ensure_ascii=False))

    # Final evaluation only if max iterations completed or threshold not reached
    if args.max_iterations == 1 or final_avg_score < args.threshold:
        print("\n--- Final Evaluation ---")
        evaluation_result = evaluate_prompt(
            args.api_mode, args.model, current_prompt, args.user_input_description
        )
        print("Final Evaluation Result:")
        print(evaluation_result)
        final_avg_score = average_satisfaction(evaluation_result)
        print(f"Average Satisfaction Score: {final_avg_score:.2f}")

    write_to_file(args.output_path, current_prompt)

    attack_results = []
    if args.test_after:
        tools = load_tools(args.tools_path) if args.tools_path else None
        test_model = args.test_model or args.model
        print("\n--- Running injection test on final prompt ---")
        attack_results = run_injection_test(
            current_prompt,
            test_model,
            apply_techniques=apply_techniques,
            separator=args.test_separator,
            tools=tools,
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
        )
        print("Report generation complete.")


if __name__ == "__main__":
    main()
