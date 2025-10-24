from typing import Dict, Any, Optional
import argparse
import json
import os
from evaluate import evaluate_prompt
from improve import improve_prompt
from attack import run_injection_test
from gen_report import generate_improvement_report, generate_evaluation_report
from prompt import parse_prompt_input, write_prompt_output, show_prompt
from webui import launch_webui


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate, improve, and test the security of system prompts using LLM APIs."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("webui", help="Launch the web UI")

    evaluate_parser = subparsers.add_parser("evaluate", help="Evaluate a prompt")

    evaluate_parser.add_argument(
        "-t",
        "--target-prompt-path",
        type=str,
        required=True,
        help="Path to the file containing the target prompt in Chat Completion message format (JSON).",
    )

    evaluate_parser.add_argument(
        "--input-mode",
        choices=["chat", "completion"],
        default="chat",
        help="Prompt format type: 'chat' for role-based messages, 'completion' for single prompt string. Default is 'chat'.",
    )

    evaluate_parser.add_argument(
        "--input-format",
        choices=["openai", "claude", "bedrock"],
        default="openai",
        help="Input message format to parse: openai, claude, or bedrock. Default is 'openai'.",
    )

    evaluate_parser.add_argument(
        "-ea",
        "--eval-api-mode",
        type=str,
        choices=["openai", "claude", "bedrock"],
        required=True,
        help="LLM API to use for evaluating the prompt (e.g., OpenAI or Claude).",
    )

    evaluate_parser.add_argument(
        "-em",
        "--eval-model",
        type=str,
        required=True,
        help="Model name for evaluation (e.g., 'gpt-4o-mini', 'claude-3-7sonnet-latest').",
    )

    evaluate_parser.add_argument(
        "-ar",
        "--aws-region",
        type=str,
        default="us-east-1",
        help="AWS region for Bedrock API mode. Default is 'us-east-1'.",
    )

    evaluate_parser.add_argument(
        "-ap",
        "--aws-profile",
        type=str,
        default=None,
        help="AWS profile name to use for Bedrock API mode. If not specified, uses default AWS credential chain.",
    )

    evaluate_parser.add_argument(
        "-ui",
        "--user-input-description",
        type=str,
        help="Description of user input fields. Helps prevent incorrect placement inside secure instruction tags.",
    )

    evaluate_parser.add_argument(
        "-o",
        "--output-path",
        type=str,
        help="Optional file path to write the evaluation result as JSON.",
    )

    evaluate_parser.add_argument(
        "-a",
        "--apply-techniques",
        nargs="+",
        choices=[
            "spotlighting",
            "random_sequence_enclosure",
            "instruction_defense",
            "role_consistency",
            "secrets_exclusion",
        ],
        help="List of techniques to apply during prompt evaluation. Use space characters to separate multiple techniques. Defaults to all if not specified.",
    )

    evaluate_parser.add_argument(
        "-rd",
        "--report-dir",
        type=str,
        help="Directory to write a full HTML and JSON evaluation report after execution.",
    )

    improve_parser = subparsers.add_parser("improve", help="Improve a prompt")

    improve_parser.add_argument(
        "-t",
        "--target-prompt-path",
        type=str,
        required=True,
        help="Path to the file containing the target prompt in Chat Completion message format (JSON).",
    )

    improve_parser.add_argument(
        "--input-mode",
        choices=["chat", "completion"],
        default="chat",
        help="Prompt format type: 'chat' for role-based messages, 'completion' for single prompt string. Default is 'chat'.",
    )

    improve_parser.add_argument(
        "--input-format",
        choices=["openai", "claude", "bedrock"],
        default="openai",
        help="Input message format to parse: openai, claude, or bedrock. Default is 'openai'.",
    )

    improve_parser.add_argument(
        "-ea",
        "--eval-api-mode",
        type=str,
        choices=["openai", "claude", "bedrock"],
        required=True,
        help="LLM API to use for evaluating and improving the prompt (e.g., OpenAI or Claude).",
    )
    improve_parser.add_argument(
        "-em",
        "--eval-model",
        type=str,
        required=True,
        help="Model name for evaluation and improvement (e.g., 'gpt-4o-mini', 'claude-3-7sonnet-latest').",
    )
    improve_parser.add_argument(
        "-aa",
        "--attack-api-mode",
        type=str,
        choices=["openai", "claude", "bedrock"],
        default=None,
        help="LLM API to use for executing attacks. If not provided, defaults to --eval-api-mode.",
    )
    improve_parser.add_argument(
        "-am",
        "--attack-model",
        type=str,
        default=None,
        help="Model to use for executing attacks. If not provided, defaults to --eval-model.",
    )

    improve_parser.add_argument(
        "-ja",
        "--judge-api-mode",
        type=str,
        choices=["openai", "claude", "bedrock"],
        default=None,
        help="LLM API to use for inserting attack payloads and judging success. If not provided, defaults to --eval-api-mode.",
    )
    improve_parser.add_argument(
        "-jm",
        "--judge-model",
        type=str,
        default=None,
        help="Model to use for inserting attack payloads and judging success. If not provided, defaults to --eval-model.",
    )

    improve_parser.add_argument(
        "-ar",
        "--aws-region",
        type=str,
        default="us-east-1",
        help="AWS region for Bedrock API mode. Default is 'us-east-1'.",
    )

    improve_parser.add_argument(
        "-ap",
        "--aws-profile",
        type=str,
        default=None,
        help="AWS profile name to use for Bedrock API mode. If not specified, uses default AWS credential chain.",
    )

    improve_parser.add_argument(
        "-ui",
        "--user-input-description",
        type=str,
        help="Description of user input fields. Helps prevent incorrect placement inside secure instruction tags.",
    )

    improve_parser.add_argument(
        "-o",
        "--output-path",
        type=str,
        help="File path to write the improved prompt as JSON.",
    )

    improve_parser.add_argument(
        "-n",
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum number of self-refinement iterations. Default is 3.",
    )

    improve_parser.add_argument(
        "--threshold",
        type=float,
        default=8.5,
        help="Score threshold (0-10) to stop refinement. If reached, iteration halts early. Default is 8.5.",
    )

    improve_parser.add_argument(
        "-a",
        "--apply-techniques",
        nargs="+",
        choices=[
            "spotlighting",
            "random_sequence_enclosure",
            "instruction_defense",
            "role_consistency",
            "secrets_exclusion",
        ],
        help="List of techniques to apply during prompt improvement. Use space characters to separate multiple techniques. Defaults to all if not specified.",
    )

    improve_parser.add_argument(
        "-ta",
        "--test-after",
        action="store_true",
        help="Run prompt injection test automatically after refinement.",
    )

    improve_parser.add_argument(
        "-ts",
        "--test-separator",
        type=str,
        default=None,
        help="Optional string to prepend to each attack payload (e.g., '\\n').",
    )

    improve_parser.add_argument(
        "-tp",
        "--tools-path",
        type=str,
        help="Path to a JSON file that defines available tools/functions for the LLM (used during attack).",
    )

    improve_parser.add_argument(
        "-rd",
        "--report-dir",
        type=str,
        help="Directory to write a full HTML and JSON report after execution.",
    )

    args = parser.parse_args()

    # Validation: Ensure --input-format and --attack-api-mode are the same
    if (
        args.command == "improve"
        and args.input_mode == "chat"
        and args.attack_api_mode
        and args.input_format != args.attack_api_mode
    ):
        parser.error(
            f"--input-format ({args.input_format}) and --attack-api-mode ({args.attack_api_mode}) must be the same."
        )

    return args


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
    if args.command == "webui":
        print("\033[36m" + "Launching web UI..." + "\033[0m")
        launch_webui()
    elif args.command == "evaluate":
        current_prompt = parse_prompt_input(
            args.target_prompt_path, args.input_mode, args.input_format
        )
        print(
            "\033[36m"
            + "\n🔍 Loaded Prompt from: "
            + args.target_prompt_path
            + "\033[0m"
        )
        print(show_prompt(current_prompt))

        evaluation = evaluate_prompt(
            args.eval_api_mode,
            args.eval_model,
            current_prompt,
            args.user_input_description,
            apply_techniques=args.apply_techniques,
            aws_region=args.aws_region,
            aws_profile=args.aws_profile,
        )

        avg_score = average_satisfaction(evaluation)
        print("\033[35m" + "\n🧪 Evaluation Result:" + "\033[0m")
        print(json.dumps(evaluation, indent=2, ensure_ascii=False))
        print(
            "\033[33m" + f"\n📊 Average Satisfaction Score: {avg_score:.2f}" + "\033[0m"
        )

        if args.output_path:
            try:
                with open(args.output_path, "w", encoding="utf-8") as f:
                    json.dump(evaluation, f, ensure_ascii=False, indent=2)
                print(
                    "\033[32m"
                    + f"\n✅ Evaluation written to: {args.output_path}"
                    + "\033[0m"
                )
            except OSError as e:
                print(
                    "\033[31m"
                    + f"\n[Error] Failed to write evaluation output: {e}"
                    + "\033[0m"
                )

        if args.report_dir:
            report_dir_path = os.path.abspath(args.report_dir)
            print(
                "\033[36m"
                + f"\n--- Generating evaluation report at {report_dir_path} ---"
                + "\033[0m"
            )
            generate_evaluation_report(
                current_prompt,
                evaluation,
                report_dir_path,
                avg_score,
                args.eval_model,
                args.eval_api_mode,
            )
            print("\033[32m" + "✅ Evaluation report generation complete." + "\033[0m")

    elif args.command == "improve":
        # Load and parse prompt
        current_prompt = parse_prompt_input(
            args.target_prompt_path, args.input_mode, args.input_format
        )
        print(
            "\033[36m"
            + "\n🔍 Loaded Prompt from: "
            + args.target_prompt_path
            + "\033[0m"
        )
        print(show_prompt(current_prompt))

        if args.attack_api_mode is None:
            args.attack_api_mode = args.eval_api_mode
        if args.attack_model is None:
            args.attack_model = args.eval_model
        if args.judge_api_mode is None:
            args.judge_api_mode = args.eval_api_mode
        if args.judge_model is None:
            args.judge_model = args.eval_model

        initial_prompt = current_prompt
        apply_techniques = args.apply_techniques or []

        initial_evaluation = evaluate_prompt(
            args.eval_api_mode,
            args.eval_model,
            initial_prompt,
            args.user_input_description,
            apply_techniques=apply_techniques,
            aws_region=args.aws_region,
            aws_profile=args.aws_profile,
        )
        initial_avg_score = average_satisfaction(initial_evaluation)
        print("\033[35m" + "\n🧪 Initial Evaluation Result:" + "\033[0m")
        print(json.dumps(initial_evaluation, indent=2, ensure_ascii=False))
        print(
            "\033[33m"
            + f"\n📊 Initial Average Satisfaction Score: {initial_avg_score:.2f}"
            + "\033[0m"
        )

        evaluation_result = initial_evaluation
        final_avg_score = initial_avg_score

        for i in range(args.max_iterations):
            print("\033[36m" + f"\n{'=' * 20} Iteration {i + 1} {'=' * 20}" + "\033[0m")
            if i > 0:
                evaluation_result = evaluate_prompt(
                    args.eval_api_mode,
                    args.eval_model,
                    current_prompt,
                    args.user_input_description,
                    apply_techniques=apply_techniques,
                    aws_region=args.aws_region,
                    aws_profile=args.aws_profile,
                )
                print("\033[35m" + "🔍 Evaluation Result:" + "\033[0m")
                print(json.dumps(evaluation_result, indent=2, ensure_ascii=False))

                final_avg_score = average_satisfaction(evaluation_result)
                print(
                    "\033[33m"
                    + f"📊 Average Satisfaction Score: {final_avg_score:.2f}"
                    + "\033[0m"
                )

                if final_avg_score >= args.threshold:
                    print(
                        "\033[32m"
                        + "✅ Prompt meets the required security threshold. Stopping refinement."
                        + "\033[0m"
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
                aws_profile=args.aws_profile,
            )
            print("\033[32m" + "\n✅ Improved Prompt:" + "\033[0m")
            print(show_prompt(current_prompt))

        if args.max_iterations == 1 or final_avg_score < args.threshold:
            evaluation_result = evaluate_prompt(
                args.eval_api_mode,
                args.eval_model,
                current_prompt,
                args.user_input_description,
                apply_techniques=apply_techniques,
                aws_region=args.aws_region,
                aws_profile=args.aws_profile,
            )
            final_avg_score = average_satisfaction(evaluation_result)
            print("\033[35m" + "\n🎯 Final Evaluation Result:" + "\033[0m")
            print(json.dumps(evaluation_result, indent=2, ensure_ascii=False))
            print(
                "\033[33m" + f"\n📈 Final Avg Score: {final_avg_score:.2f}" + "\033[0m"
            )

        # Write the improved prompt to output file
        if args.output_path:
            print(
                "\033[36m"
                + "\n--- Writing Improved Prompt to Output File ---"
                + "\033[0m"
            )
            try:
                write_prompt_output(
                    args.output_path,
                    current_prompt,
                    args.input_mode,
                    args.input_format,
                )
                print(
                    "\033[32m" + f"✅ Prompt written to: {args.output_path}" + "\033[0m"
                )
            except OSError as e:
                print(
                    "\033[31m"
                    + f"\n[Error] Failed to write prompt output: {e}"
                    + "\033[0m"
                )

        # Run injection test if requested
        attack_results = []
        if args.test_after:
            tools = load_tools(args.tools_path) if args.tools_path else None
            print(
                "\033[36m"
                + "\n--- Running injection test on final prompt ---"
                + "\033[0m"
            )
            attack_results = run_injection_test(
                current_prompt,
                args.attack_api_mode,
                args.attack_model,
                args.judge_api_mode,
                args.judge_model,
                apply_techniques,
                args.test_separator,
                tools,
                args.aws_region,
                args.aws_profile,
            )

        if args.report_dir:
            report_dir_path = os.path.abspath(args.report_dir)
            print(
                "\033[36m"
                + f"\n--- Generating report at {report_dir_path} ---"
                + "\033[0m"
            )
            generate_improvement_report(
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
            print("\033[32m" + "✅ Report generation complete." + "\033[0m")


if __name__ == "__main__":
    main()
