from typing import Dict, Any, Optional
import argparse
import json
import os
from prompt_hardener.attack import run_injection_test
from prompt_hardener.gen_report import (
    generate_improvement_report,
    generate_evaluation_report,
)
from prompt_hardener.prompt import (
    parse_prompt_input,
    write_prompt_output,
    show_prompt,
)
from prompt_hardener.prompt_improvement import run_improvement_loop
from prompt_hardener.webui import launch_webui


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate, improve, and test the security of system prompts using LLM APIs."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("webui", help="Launch the web UI")

    # --- init subcommand ---
    init_parser = subparsers.add_parser(
        "init", help="Create a new agent_spec.yaml from a template"
    )
    init_parser.add_argument(
        "--type",
        choices=["chatbot", "rag", "agent", "mcp-agent"],
        default="chatbot",
        help="Agent type template to use. Default is 'chatbot'.",
    )
    init_parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="./agent_spec.yaml",
        help="Output file path. Default is './agent_spec.yaml'.",
    )

    # --- validate subcommand ---
    validate_parser = subparsers.add_parser(
        "validate", help="Validate an agent_spec.yaml file"
    )
    validate_parser.add_argument(
        "spec_path",
        type=str,
        help="Path to the agent_spec.yaml file to validate.",
    )

    # --- analyze subcommand ---
    analyze_parser = subparsers.add_parser(
        "analyze", help="Run static security analysis on an agent_spec.yaml"
    )
    analyze_parser.add_argument(
        "spec_path",
        type=str,
        help="Path to the agent_spec.yaml file to analyze.",
    )
    analyze_parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Output file path for the report. Defaults to stdout.",
    )
    analyze_parser.add_argument(
        "--format",
        choices=["json", "markdown", "both"],
        default="json",
        help="Output format. Default is 'json'.",
    )
    analyze_parser.add_argument(
        "-l",
        "--layers",
        nargs="+",
        choices=["prompt", "tool", "architecture"],
        default=None,
        help="Layers to analyze. Defaults to all applicable layers.",
    )

    # --- remediate subcommand ---
    remediate_parser = subparsers.add_parser(
        "remediate",
        help="Generate actionable remediations from static analysis findings",
    )
    remediate_parser.add_argument(
        "spec_path",
        type=str,
        help="Path to the agent_spec.yaml file to remediate.",
    )
    remediate_parser.add_argument(
        "-l",
        "--layers",
        nargs="+",
        choices=["prompt", "tool", "architecture"],
        default=None,
        help="Layers to remediate. Defaults to all applicable layers for the spec type.",
    )
    remediate_parser.add_argument(
        "-n",
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum iterations for prompt improvement. Default is 3.",
    )
    remediate_parser.add_argument(
        "--threshold",
        type=float,
        default=8.5,
        help="Score threshold (0-10) to stop prompt refinement. Default is 8.5.",
    )
    remediate_parser.add_argument(
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
        help="Techniques to apply during prompt improvement. Defaults to all.",
    )
    remediate_parser.add_argument(
        "-ea",
        "--eval-api-mode",
        type=str,
        choices=["openai", "claude", "bedrock"],
        required=True,
        help="LLM API to use for evaluation and improvement.",
    )
    remediate_parser.add_argument(
        "-em",
        "--eval-model",
        type=str,
        required=True,
        help="Model name for evaluation and improvement.",
    )
    remediate_parser.add_argument(
        "-o",
        "--output-path",
        type=str,
        default=None,
        help="File path to write updated agent_spec.yaml with improved system prompt.",
    )
    remediate_parser.add_argument(
        "-rd",
        "--report-dir",
        type=str,
        default=None,
        help="Directory to write the remediation report as JSON.",
    )
    remediate_parser.add_argument(
        "-ar",
        "--aws-region",
        type=str,
        default="us-east-1",
        help="AWS region for Bedrock API mode. Default is 'us-east-1'.",
    )
    remediate_parser.add_argument(
        "-ap",
        "--aws-profile",
        type=str,
        default=None,
        help="AWS profile name for Bedrock API mode.",
    )

    # --- simulate subcommand ---
    simulate_parser = subparsers.add_parser(
        "simulate", help="Run attack simulation against an agent_spec.yaml"
    )
    simulate_parser.add_argument(
        "spec_path",
        type=str,
        help="Path to the agent_spec.yaml file to simulate against.",
    )
    simulate_parser.add_argument(
        "--scenarios",
        type=str,
        default=None,
        help="Path to a custom scenario catalog directory. Defaults to built-in catalog.",
    )
    simulate_parser.add_argument(
        "--categories",
        type=str,
        default=None,
        help="Comma-separated list of scenario categories to include.",
    )
    simulate_parser.add_argument(
        "-l",
        "--layers",
        type=str,
        default=None,
        help="Comma-separated list of target layers to include (prompt, tool, architecture).",
    )
    simulate_parser.add_argument(
        "-ea",
        "--eval-api-mode",
        type=str,
        choices=["openai", "claude", "bedrock"],
        required=True,
        help="LLM API to use (also the default for attack and judge).",
    )
    simulate_parser.add_argument(
        "-em",
        "--eval-model",
        type=str,
        required=True,
        help="Model name (also the default for attack and judge).",
    )
    simulate_parser.add_argument(
        "-aa",
        "--attack-api-mode",
        type=str,
        choices=["openai", "claude", "bedrock"],
        default=None,
        help="LLM API for executing attacks. Defaults to --eval-api-mode.",
    )
    simulate_parser.add_argument(
        "-am",
        "--attack-model",
        type=str,
        default=None,
        help="Model for executing attacks. Defaults to --eval-model.",
    )
    simulate_parser.add_argument(
        "-ja",
        "--judge-api-mode",
        type=str,
        choices=["openai", "claude", "bedrock"],
        default=None,
        help="LLM API for judging attack success. Defaults to --eval-api-mode.",
    )
    simulate_parser.add_argument(
        "-jm",
        "--judge-model",
        type=str,
        default=None,
        help="Model for judging attack success. Defaults to --eval-model.",
    )
    simulate_parser.add_argument(
        "-ts",
        "--separator",
        type=str,
        default=None,
        help="Optional string to prepend to each attack payload.",
    )
    simulate_parser.add_argument(
        "-o",
        "--output-path",
        type=str,
        default=None,
        help="File path to write the simulation report as JSON.",
    )
    simulate_parser.add_argument(
        "-ar",
        "--aws-region",
        type=str,
        default="us-east-1",
        help="AWS region for Bedrock API mode. Default is 'us-east-1'.",
    )
    simulate_parser.add_argument(
        "-ap",
        "--aws-profile",
        type=str,
        default=None,
        help="AWS profile name for Bedrock API mode.",
    )

    # --- report subcommand ---
    report_parser = subparsers.add_parser(
        "report",
        help="Generate a formatted report from analyze/simulate/remediate JSON output",
    )
    report_parser.add_argument(
        "results_path",
        type=str,
        help="Path to a JSON result file from analyze, simulate, or remediate.",
    )
    report_parser.add_argument(
        "-f",
        "--format",
        choices=["html", "json", "markdown"],
        default="markdown",
        help="Output format. Default is 'markdown'.",
    )
    report_parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Output file path. Defaults to stdout.",
    )

    # --- diff subcommand ---
    diff_parser = subparsers.add_parser(
        "diff", help="Show differences between two agent_spec.yaml files"
    )
    diff_parser.add_argument(
        "before_path",
        type=str,
        help="Path to the first (before) agent_spec.yaml file.",
    )
    diff_parser.add_argument(
        "after_path",
        type=str,
        help="Path to the second (after) agent_spec.yaml file.",
    )
    diff_parser.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format. Default is 'text'.",
    )

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


def run_init(args: argparse.Namespace) -> None:
    import shutil
    from pathlib import Path

    output_path = Path(args.output)
    if output_path.exists():
        print(
            "\033[31m"
            + "[Error] %s already exists. Use a different path or remove the file first."
            % args.output
            + "\033[0m"
        )
        raise SystemExit(1)

    templates_dir = Path(__file__).parent / "templates"
    template_file = templates_dir / ("%s.yaml" % args.type)
    if not template_file.exists():
        print(
            "\033[31m"
            + "[Error] Template not found for type '%s'" % args.type
            + "\033[0m"
        )
        raise SystemExit(1)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(template_file), str(output_path))
    print("Created %s (type: %s)" % (args.output, args.type))
    print("Edit the file to customize your agent specification, then run:")
    print("  prompt-hardener validate %s" % args.output)


def run_validate(args: argparse.Namespace) -> None:
    from prompt_hardener.agent_spec import load_yaml, validate

    try:
        data = load_yaml(args.spec_path)
    except ValueError as e:
        print("\033[31m" + str(e) + "\033[0m")
        raise SystemExit(1)

    result = validate(data)

    # Print warnings
    for w in result.warnings:
        print("  " + str(w))

    if not result.is_valid:
        print("%s has %d error(s):" % (args.spec_path, len(result.errors)))
        for err in result.errors:
            print("  " + str(err))
        raise SystemExit(1)

    agent_type = data.get("type", "unknown")
    agent_name = data.get("name", "unnamed")
    print("%s is valid (type: %s, name: %s)" % (args.spec_path, agent_type, agent_name))
    if result.warnings:
        print("  %d warning(s)" % len(result.warnings))


def run_simulate_cmd(args: argparse.Namespace) -> None:
    from prompt_hardener.progress import ProgressBar
    from prompt_hardener.simulate import run_simulate

    # Resolve fallback parameters
    attack_api_mode = args.attack_api_mode or args.eval_api_mode
    attack_model = args.attack_model or args.eval_model
    judge_api_mode = args.judge_api_mode or args.eval_api_mode
    judge_model = args.judge_model or args.eval_model

    # Parse comma-separated filters
    categories = (
        [c.strip() for c in args.categories.split(",")] if args.categories else None
    )
    layers = (
        [layer.strip() for layer in args.layers.split(",")] if args.layers else None
    )

    # We need a mutable reference so the callback can call advance()
    pb_holder = [None]  # type: list

    def _on_progress(current: int, total: int, scenario_id: str) -> None:
        pb = pb_holder[0]
        if pb is None:
            # Lazily create ProgressBar on first call (total is now known)
            pb_holder[0] = ProgressBar(total=total, message="Simulating")
            pb_holder[0].__enter__()
            pb = pb_holder[0]
        pb.advance(scenario_id)

    try:
        report = run_simulate(
            spec_path=args.spec_path,
            attack_api_mode=attack_api_mode,
            attack_model=attack_model,
            judge_api_mode=judge_api_mode,
            judge_model=judge_model,
            scenarios_dir=args.scenarios,
            categories=categories,
            layers=layers,
            separator=args.separator,
            aws_region=args.aws_region,
            aws_profile=args.aws_profile,
            on_progress=_on_progress,
        )
    except ValueError as e:
        print("\033[31m" + str(e) + "\033[0m")
        raise SystemExit(1)
    finally:
        if pb_holder[0] is not None:
            pb_holder[0].__exit__(None, None, None)

    report_dict = report.to_dict()
    json_output = json.dumps(report_dict, indent=2, ensure_ascii=False)

    # Console summary
    s = report.summary
    print(
        "\n--- Simulation Summary ---\n"
        "Total: %d | Blocked: %d | Succeeded: %d | Block rate: %.1f%%"
        % (s.total, s.blocked, s.succeeded, s.block_rate * 100)
    )

    if args.output_path:
        try:
            with open(args.output_path, "w", encoding="utf-8") as f:
                f.write(json_output)
            print("Simulation report written to %s" % args.output_path)
        except OSError as e:
            print("\033[31m[Error] Failed to write report: %s\033[0m" % e)
    else:
        print(json_output)


def run_analyze_cmd(args: argparse.Namespace) -> None:
    from prompt_hardener.analyze.engine import run_analyze
    from prompt_hardener.analyze.markdown import render_markdown
    from prompt_hardener.progress import Spinner

    try:
        with Spinner("Analyzing (static rules)..."):
            report = run_analyze(
                args.spec_path,
                layers=args.layers,
            )
    except ValueError as e:
        print("\033[31m" + str(e) + "\033[0m")
        raise SystemExit(1)

    report_dict = report.to_dict()
    fmt = getattr(args, "format", "json")

    json_output = json.dumps(report_dict, indent=2, ensure_ascii=False)
    md_output = render_markdown(report) if fmt in ("markdown", "both") else None

    if args.output:
        if fmt == "json":
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_output)
            print("Analyze report written to %s" % args.output)
        elif fmt == "markdown":
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(md_output)
            print("Analyze report written to %s" % args.output)
        elif fmt == "both":
            # Write JSON
            json_path = args.output
            with open(json_path, "w", encoding="utf-8") as f:
                f.write(json_output)
            # Write Markdown alongside
            md_path = (
                args.output.rsplit(".", 1)[0] + ".md"
                if "." in args.output
                else args.output + ".md"
            )
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(md_output)
            print("Analyze reports written to %s and %s" % (json_path, md_path))
    else:
        if fmt == "json":
            print(json_output)
        elif fmt == "markdown":
            print(md_output)
        elif fmt == "both":
            print(json_output)
            print("\n---\n")
            print(md_output)


def run_remediate_cmd(args: argparse.Namespace) -> None:
    from prompt_hardener.progress import Spinner
    from prompt_hardener.remediate.engine import run_remediate

    spinner = Spinner("Remediating...")

    def _on_progress(message: str) -> None:
        spinner.update(message)

    try:
        with spinner:
            report = run_remediate(
                spec_path=args.spec_path,
                eval_api_mode=args.eval_api_mode,
                eval_model=args.eval_model,
                layers=args.layers,
                max_iterations=args.max_iterations,
                threshold=args.threshold,
                apply_techniques=args.apply_techniques,
                output_path=args.output_path,
                aws_region=args.aws_region,
                aws_profile=args.aws_profile,
                on_progress=_on_progress,
            )
    except (ValueError, SystemExit) as e:
        print("\033[31m" + str(e) + "\033[0m")
        raise SystemExit(1)

    report_dict = report.to_dict()
    json_output = json.dumps(report_dict, indent=2, ensure_ascii=False)

    # Console summary
    print("\n--- Remediation Summary ---")
    if report.prompt is not None:
        print("Prompt: %s" % report.prompt.changes)
    if report.tool is not None:
        print("Tool: %d recommendation(s)" % len(report.tool))
        for r in report.tool:
            print("  [%s] %s" % (r.severity.upper(), r.title))
    if report.architecture is not None:
        print("Architecture: %d recommendation(s)" % len(report.architecture))
        for r in report.architecture:
            print("  [%s] %s" % (r.severity.upper(), r.title))
    if report.applied_patches:
        print("Auto-applied patches:")
        for desc in report.applied_patches:
            print("  - %s" % desc)

    if args.output_path:
        print("Updated agent spec written to %s" % args.output_path)

    if args.report_dir:
        import os

        os.makedirs(args.report_dir, exist_ok=True)
        report_path = os.path.join(args.report_dir, "remediation_report.json")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(json_output)
            print("Remediation report written to %s" % report_path)
        except OSError as e:
            print("\033[31m[Error] Failed to write report: %s\033[0m" % e)
    else:
        print(json_output)


def run_report_cmd(args):
    # type: (argparse.Namespace) -> None
    from prompt_hardener.report import generate_report

    fmt = getattr(args, "format", "markdown")
    try:
        output = generate_report(
            results_path=args.results_path,
            output_format=fmt,
            output_path=args.output,
        )
    except (ValueError, OSError) as e:
        print("\033[31m" + str(e) + "\033[0m")
        raise SystemExit(1)

    if args.output:
        print("Report written to %s" % args.output)
    else:
        print(output)


def run_diff_cmd(args):
    # type: (argparse.Namespace) -> None
    from prompt_hardener.diff import run_diff

    fmt = getattr(args, "format", "text")
    try:
        output = run_diff(
            before_path=args.before_path,
            after_path=args.after_path,
            output_format=fmt,
        )
    except (ValueError, OSError) as e:
        print("\033[31m" + str(e) + "\033[0m")
        raise SystemExit(1)

    print(output)


def _prompt_input_to_agent_spec(prompt_input, args):
    """Build a temporary AgentSpec from PromptInput + CLI args for analyze."""
    from prompt_hardener.models import AgentSpec, ProviderConfig
    from prompt_hardener.remediate.prompt_layer import _extract_system_prompt

    system_prompt = _extract_system_prompt(prompt_input)
    api_mode = args.eval_api_mode
    model = args.eval_model

    # Extract non-system messages
    messages = None
    if prompt_input.messages:
        messages = [m for m in prompt_input.messages if m.get("role") != "system"]
        if not messages:
            messages = None

    return AgentSpec(
        version="1.0",
        type="chatbot",
        name="(from prompt file)",
        system_prompt=system_prompt,
        provider=ProviderConfig(api=api_mode, model=model),
        messages=messages,
        user_input_description=getattr(args, "user_input_description", None),
    )


def main() -> None:
    args = parse_args()
    if args.command == "init":
        run_init(args)
    elif args.command == "validate":
        run_validate(args)
    elif args.command == "analyze":
        run_analyze_cmd(args)
    elif args.command == "remediate":
        run_remediate_cmd(args)
    elif args.command == "simulate":
        run_simulate_cmd(args)
    elif args.command == "report":
        run_report_cmd(args)
    elif args.command == "diff":
        run_diff_cmd(args)
    elif args.command == "webui":
        print("\033[36m" + "Launching web UI..." + "\033[0m")
        launch_webui()
    elif args.command == "evaluate":
        from prompt_hardener.evaluate import evaluate_prompt
        from prompt_hardener.utils import average_satisfaction

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

        # Build temporary AgentSpec for context only, then run legacy LLM evaluation.
        temp_spec = _prompt_input_to_agent_spec(current_prompt, args)
        evaluation = evaluate_prompt(
            args.eval_api_mode,
            args.eval_model,
            current_prompt,
            args.user_input_description,
            apply_techniques=args.apply_techniques,
            findings=None,
            agent_context=temp_spec.to_agent_context(),
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

        apply_techniques = args.apply_techniques or []

        # Use shared improvement loop
        result = run_improvement_loop(
            prompt_input=current_prompt,
            eval_api_mode=args.eval_api_mode,
            eval_model=args.eval_model,
            attack_api_mode=args.attack_api_mode,
            max_iterations=args.max_iterations,
            threshold=args.threshold,
            apply_techniques=apply_techniques,
            user_input_description=args.user_input_description,
            aws_region=args.aws_region,
            aws_profile=args.aws_profile,
        )

        initial_prompt = result.initial_prompt
        initial_evaluation = result.initial_evaluation
        initial_avg_score = result.initial_score
        improved_prompt = result.improved_prompt
        evaluation_result = result.final_evaluation
        final_avg_score = result.final_score

        print("\033[35m" + "\n🧪 Initial Evaluation Result:" + "\033[0m")
        print(json.dumps(initial_evaluation, indent=2, ensure_ascii=False))
        print(
            "\033[33m"
            + f"\n📊 Initial Average Satisfaction Score: {initial_avg_score:.2f}"
            + "\033[0m"
        )
        print("\033[35m" + "\n🎯 Final Evaluation Result:" + "\033[0m")
        print(json.dumps(evaluation_result, indent=2, ensure_ascii=False))
        print("\033[33m" + f"\n📈 Final Avg Score: {final_avg_score:.2f}" + "\033[0m")
        print("\033[32m" + "\n✅ Improved Prompt:" + "\033[0m")
        print(show_prompt(improved_prompt))

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
                    improved_prompt,
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
                improved_prompt,
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
                improved_prompt,
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
