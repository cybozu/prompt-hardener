import json
import tempfile
import shutil
import sys
import subprocess
from pathlib import Path

import gradio as gr
import yaml

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_TEMPLATES_DIR = Path(__file__).parent / "templates"

# ---------------------------------------------------------------------------
# Legacy backend functions (subprocess-based)
# ---------------------------------------------------------------------------


def run_improvement(
    prompt,
    input_mode,
    input_format,
    eval_api_mode,
    eval_model,
    attack_api_mode,
    attack_model,
    judge_api_mode,
    judge_model,
    description,
    iterations,
    threshold,
    techniques,
    test,
    separator,
    tools_json,
    aws_region,
    aws_profile,
):
    report_dir = Path(tempfile.mkdtemp())
    report_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        prompt_path = Path(tmpdir) / "prompt.json"
        output_path = Path(tmpdir) / "out.json"
        tools_path = None

        prompt_path.write_text(prompt, encoding="utf-8")
        if tools_json:
            tools_path = Path(tmpdir) / "tools.json"
            tools_path.write_text(tools_json, encoding="utf-8")

        cmd = [
            sys.executable,
            str(Path(__file__).parent / "main.py"),
            "improve",
            "--target-prompt-path",
            str(prompt_path),
            "--input-mode",
            input_mode,
            "--input-format",
            input_format,
            "--eval-api-mode",
            eval_api_mode,
            "--eval-model",
            eval_model,
            "--output-path",
            str(output_path),
            "--max-iterations",
            str(iterations),
            "--threshold",
            str(threshold),
            "--report-dir",
            str(report_dir),
        ]
        if description:
            cmd += ["--user-input-description", description]
        if techniques:
            cmd += ["--apply-techniques"] + techniques
        if test:
            if attack_api_mode:
                cmd += ["--attack-api-mode", attack_api_mode]
            if attack_model:
                cmd += ["--attack-model", attack_model]
            if judge_api_mode:
                cmd += ["--judge-api-mode", judge_api_mode]
            if judge_model:
                cmd += ["--judge-model", judge_model]
            cmd += ["--test-after"]
        if separator:
            cmd += ["--test-separator", separator]
        if tools_path:
            cmd += ["--tools-path", str(tools_path)]
        if aws_region:
            cmd += ["--aws-region", aws_region]
        if aws_profile:
            cmd += ["--aws-profile", aws_profile]

        try:
            subprocess.run(cmd, text=True, check=True)
            status = "✅ Complete"
        except subprocess.CalledProcessError as e:
            status = f"❌ Error: {e.stderr or e.stdout}"

        report_file = next(report_dir.glob("prompt_security_report_*.html"), None)
        json_file = next(
            report_dir.glob("prompt_security_report_*_attack_results.json"), None
        )

        html_tmp = tempfile.NamedTemporaryFile(suffix=".html", delete=False)
        json_tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)

        if report_file:
            shutil.copy(report_file, html_tmp.name)
        if json_file:
            shutil.copy(json_file, json_tmp.name)

        html_tmp.close()
        json_tmp.close()

        if report_file and json_file:
            return status, html_tmp.name, json_tmp.name
        else:
            return status, None, None


def run_evaluation(
    prompt,
    input_mode,
    input_format,
    eval_api_mode,
    eval_model,
    description,
    techniques,
    aws_region,
    aws_profile,
):
    report_dir = Path(tempfile.mkdtemp())
    report_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        prompt_path = Path(tmpdir) / "prompt.json"
        output_path = Path(tmpdir) / "evaluation.json"

        prompt_path.write_text(prompt, encoding="utf-8")

        cmd = [
            sys.executable,
            str(Path(__file__).parent / "main.py"),
            "evaluate",
            "--target-prompt-path",
            str(prompt_path),
            "--input-mode",
            input_mode,
            "--input-format",
            input_format,
            "--eval-api-mode",
            eval_api_mode,
            "--eval-model",
            eval_model,
            "--output-path",
            str(output_path),
            "--report-dir",
            str(report_dir),
        ]
        if description:
            cmd += ["--user-input-description", description]
        if techniques:
            cmd += ["--apply-techniques"] + techniques
        if aws_region:
            cmd += ["--aws-region", aws_region]
        if aws_profile:
            cmd += ["--aws-profile", aws_profile]

        try:
            result = subprocess.run(cmd, text=True, check=True, capture_output=True)
            status = "✅ Evaluation Complete"
            stdout_output = result.stdout

            # Read the evaluation result from the output file
            evaluation_result = ""
            if output_path.exists():
                evaluation_result = output_path.read_text(encoding="utf-8")

            # Find generated report files
            html_report = next(report_dir.glob("prompt_evaluation_report_*.html"), None)

            # Create temporary files for download
            eval_tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
            html_tmp = tempfile.NamedTemporaryFile(suffix=".html", delete=False)

            if evaluation_result:
                eval_tmp.write(evaluation_result.encode("utf-8"))
            eval_tmp.close()

            if html_report:
                shutil.copy(html_report, html_tmp.name)
            html_tmp.close()

            return (
                status,
                stdout_output,
                eval_tmp.name if evaluation_result else None,
                html_tmp.name if html_report else None,
            )

        except subprocess.CalledProcessError as e:
            error_output = e.stderr or e.stdout or str(e)
            status = f"❌ Error: {error_output}"
            return status, error_output, None, None


# ---------------------------------------------------------------------------
# New backend functions (direct Python import, no subprocess)
# ---------------------------------------------------------------------------


def load_template(agent_type):
    """Load a template YAML file for the given agent type and return its content."""
    template_path = _TEMPLATES_DIR / ("%s.yaml" % agent_type)
    if not template_path.exists():
        return "# Error: Template not found for type '%s'" % agent_type
    return template_path.read_text(encoding="utf-8")


def upload_yaml(file):
    """Read an uploaded YAML file and return its content as a string."""
    if file is None:
        return ""
    file_path = Path(str(file))
    return file_path.read_text(encoding="utf-8")


def validate_yaml_text(yaml_text):
    """Parse YAML text and run agent_spec validation. Returns result string."""
    if not yaml_text or not yaml_text.strip():
        return "No YAML content to validate."
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        return "YAML Parse Error:\n%s" % str(e)

    if not isinstance(data, dict):
        return "Error: Expected a YAML mapping at top level."

    from prompt_hardener.agent_spec import validate

    result = validate(data)
    lines = []
    if result.is_valid and not result.warnings:
        lines.append("✅ Validation passed. No errors or warnings.")
    else:
        if result.errors:
            lines.append("❌ Errors (%d):" % len(result.errors))
            for err in result.errors:
                lines.append("  %s" % str(err))
        if result.warnings:
            lines.append("⚠️ Warnings (%d):" % len(result.warnings))
            for w in result.warnings:
                lines.append("  %s" % str(w))
        if result.is_valid:
            lines.append("")
            lines.append("✅ Validation passed (with warnings).")
    return "\n".join(lines)


def download_yaml(yaml_text):
    """Write YAML text to a temp file and return its path for download."""
    if not yaml_text or not yaml_text.strip():
        return None
    tmp = tempfile.NamedTemporaryFile(
        suffix=".yaml", delete=False, mode="w", encoding="utf-8"
    )
    tmp.write(yaml_text)
    tmp.close()
    return tmp.name


def run_analyze_webui(spec_file, layers, eval_api_mode, eval_model,
                      techniques, aws_region, aws_profile):
    """Run static analysis (+ optional LLM eval) on an agent spec."""
    if spec_file is None:
        return "❌ Error: No spec file uploaded", "", None, None

    from prompt_hardener.analyze.engine import run_analyze
    from prompt_hardener.report import render_analyze_markdown, render_analyze_html

    try:
        spec_path = str(spec_file)

        report = run_analyze(
            spec_path,
            layers=layers or None,
            eval_api_mode=eval_api_mode or None,
            eval_model=eval_model or None,
            apply_techniques=techniques or None,
            aws_region=aws_region or None,
            aws_profile=aws_profile or None,
        )

        report_dict = report.to_dict()
        json_str = json.dumps(report_dict, indent=2, ensure_ascii=False)
        md_str = render_analyze_markdown(report_dict)
        html_str = render_analyze_html(report_dict)

        json_tmp = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        )
        json_tmp.write(json_str)
        json_tmp.close()

        html_tmp = tempfile.NamedTemporaryFile(
            suffix=".html", delete=False, mode="w", encoding="utf-8"
        )
        html_tmp.write(html_str)
        html_tmp.close()

        return "✅ Analysis Complete", md_str, json_tmp.name, html_tmp.name

    except Exception as e:
        return "❌ Error: %s" % str(e), "", None, None


def run_simulate_webui(spec_file, attack_api_mode, attack_model,
                       judge_api_mode, judge_model,
                       categories, layers, separator,
                       aws_region, aws_profile):
    """Run attack simulation on an agent spec."""
    if spec_file is None:
        return "❌ Error: No spec file uploaded", "", None, None

    from prompt_hardener.simulate import run_simulate
    from prompt_hardener.report import render_simulate_markdown, render_simulate_html

    try:
        spec_path = str(spec_file)

        if not attack_api_mode or not attack_model:
            return "❌ Error: Attack API and Model are required", "", None, None
        if not judge_api_mode or not judge_model:
            return "❌ Error: Judge API and Model are required", "", None, None

        report = run_simulate(
            spec_path,
            attack_api_mode=attack_api_mode,
            attack_model=attack_model,
            judge_api_mode=judge_api_mode,
            judge_model=judge_model,
            categories=categories or None,
            layers=layers or None,
            separator=separator or None,
            aws_region=aws_region or None,
            aws_profile=aws_profile or None,
        )

        report_dict = report.to_dict()
        json_str = json.dumps(report_dict, indent=2, ensure_ascii=False)
        md_str = render_simulate_markdown(report_dict)
        html_str = render_simulate_html(report_dict)

        json_tmp = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        )
        json_tmp.write(json_str)
        json_tmp.close()

        html_tmp = tempfile.NamedTemporaryFile(
            suffix=".html", delete=False, mode="w", encoding="utf-8"
        )
        html_tmp.write(html_str)
        html_tmp.close()

        return "✅ Simulation Complete", md_str, json_tmp.name, html_tmp.name

    except Exception as e:
        return "❌ Error: %s" % str(e), "", None, None


def run_remediate_webui(spec_file, layers, eval_api_mode, eval_model,
                        max_iterations, threshold,
                        techniques, aws_region, aws_profile):
    """Run remediation on an agent spec."""
    if spec_file is None:
        return "❌ Error: No spec file uploaded", "", None, None, None

    from prompt_hardener.remediate.engine import run_remediate
    from prompt_hardener.report import render_remediate_markdown, render_remediate_html

    try:
        spec_path = str(spec_file)

        if not eval_api_mode or not eval_model:
            return "❌ Error: Eval API and Model are required", "", None, None, None

        # Create temp path for improved spec output
        output_tmp = tempfile.NamedTemporaryFile(
            suffix=".yaml", delete=False, mode="w", encoding="utf-8"
        )
        output_tmp.close()

        report = run_remediate(
            spec_path,
            eval_api_mode=eval_api_mode,
            eval_model=eval_model,
            layers=layers or None,
            max_iterations=int(max_iterations),
            threshold=float(threshold),
            apply_techniques=techniques or None,
            output_path=output_tmp.name,
            aws_region=aws_region or None,
            aws_profile=aws_profile or None,
        )

        report_dict = report.to_dict()
        json_str = json.dumps(report_dict, indent=2, ensure_ascii=False)
        md_str = render_remediate_markdown(report_dict)
        html_str = render_remediate_html(report_dict)

        json_tmp = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w", encoding="utf-8"
        )
        json_tmp.write(json_str)
        json_tmp.close()

        html_tmp = tempfile.NamedTemporaryFile(
            suffix=".html", delete=False, mode="w", encoding="utf-8"
        )
        html_tmp.write(html_str)
        html_tmp.close()

        # Check if the output spec was actually written
        improved_spec_path = output_tmp.name
        if not Path(improved_spec_path).stat().st_size:
            improved_spec_path = None

        return "✅ Remediation Complete", md_str, json_tmp.name, html_tmp.name, improved_spec_path

    except Exception as e:
        return "❌ Error: %s" % str(e), "", None, None, None


def run_report_webui(results_file, output_format):
    """Generate a formatted report from a JSON results file."""
    if results_file is None:
        return "❌ Error: No results file uploaded", "", None

    from prompt_hardener.report import generate_report

    try:
        results_path = str(results_file)
        fmt = output_format or "markdown"

        output = generate_report(results_path, output_format=fmt)

        # For markdown, show inline and also provide download
        md_preview = ""
        if fmt == "markdown":
            md_preview = output

        suffix = {"markdown": ".md", "html": ".html", "json": ".json"}.get(fmt, ".txt")
        out_tmp = tempfile.NamedTemporaryFile(
            suffix=suffix, delete=False, mode="w", encoding="utf-8"
        )
        out_tmp.write(output)
        out_tmp.close()

        return "✅ Report Generated (%s)" % fmt, md_preview, out_tmp.name

    except Exception as e:
        return "❌ Error: %s" % str(e), "", None


def run_diff_webui(before_file, after_file):
    """Compare two agent_spec.yaml files and show differences."""
    if before_file is None or after_file is None:
        return "❌ Error: Both Before and After files are required", ""

    from prompt_hardener.diff import run_diff

    try:
        before_path = str(before_file)
        after_path = str(after_file)

        md_output = run_diff(before_path, after_path, output_format="markdown")

        return "✅ Diff Complete", md_output

    except Exception as e:
        return "❌ Error: %s" % str(e), ""


# ---------------------------------------------------------------------------
# Gradio UI
# ---------------------------------------------------------------------------

with gr.Blocks() as demo:
    gr.Markdown("# Prompt Hardener Web UI")

    with gr.Tabs():
        # ---------------------------------------------------------------
        # Tab 1: Agent Spec
        # ---------------------------------------------------------------
        with gr.TabItem("Agent Spec"):
            gr.Markdown("## Create, edit, and validate agent_spec.yaml")

            with gr.Row():
                with gr.Column():
                    spec_agent_type = gr.Dropdown(
                        choices=["chatbot", "rag", "agent", "mcp-agent"],
                        value="chatbot",
                        label="Agent Type",
                    )
                    spec_load_btn = gr.Button("Load Template")
                    spec_upload = gr.File(
                        label="Upload Existing YAML",
                        file_types=[".yaml", ".yml"],
                    )
                    spec_editor = gr.Code(
                        language="yaml",
                        label="YAML Editor",
                        lines=25,
                    )

                with gr.Column():
                    spec_validate_btn = gr.Button("Validate", variant="primary")
                    spec_validation_result = gr.Textbox(
                        label="Validation Result",
                        lines=10,
                    )
                    spec_download_btn = gr.Button("Download YAML")
                    spec_download_file = gr.File(label="Download YAML")

            spec_load_btn.click(
                load_template,
                inputs=[spec_agent_type],
                outputs=[spec_editor],
            )
            spec_upload.change(
                upload_yaml,
                inputs=[spec_upload],
                outputs=[spec_editor],
            )
            spec_validate_btn.click(
                validate_yaml_text,
                inputs=[spec_editor],
                outputs=[spec_validation_result],
            )
            spec_download_btn.click(
                download_yaml,
                inputs=[spec_editor],
                outputs=[spec_download_file],
            )

        # ---------------------------------------------------------------
        # Tab 2: Analyze
        # ---------------------------------------------------------------
        with gr.TabItem("Analyze"):
            gr.Markdown("## Static analysis + optional LLM evaluation")

            with gr.Row():
                with gr.Column():
                    analyze_spec = gr.File(
                        label="Upload agent_spec.yaml",
                        file_types=[".yaml", ".yml"],
                    )
                    analyze_layers = gr.CheckboxGroup(
                        ["prompt", "tool", "architecture"],
                        label="Target Layers",
                        info="Leave empty to analyze all applicable layers.",
                    )
                    analyze_eval_api = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        label="Eval API (optional, for LLM evaluation)",
                    )
                    analyze_eval_model = gr.Textbox(
                        label="Eval Model (optional)",
                        placeholder="e.g., gpt-4o",
                    )
                    analyze_techniques = gr.CheckboxGroup(
                        [
                            "spotlighting",
                            "random_sequence_enclosure",
                            "instruction_defense",
                            "role_consistency",
                            "secrets_exclusion",
                        ],
                        label="Techniques (optional)",
                    )
                    analyze_aws_region = gr.Textbox(
                        label="AWS Region (optional)",
                        placeholder="e.g., us-east-1",
                    )
                    analyze_aws_profile = gr.Textbox(
                        label="AWS Profile (optional)",
                        placeholder="e.g., default",
                    )

                with gr.Column():
                    analyze_run_btn = gr.Button("Run Analysis", variant="primary")
                    analyze_status = gr.Textbox(label="Status")
                    analyze_report_md = gr.Markdown(label="Report")
                    analyze_json_dl = gr.File(label="Download JSON")
                    analyze_html_dl = gr.File(label="Download HTML")

            analyze_run_btn.click(
                run_analyze_webui,
                inputs=[
                    analyze_spec,
                    analyze_layers,
                    analyze_eval_api,
                    analyze_eval_model,
                    analyze_techniques,
                    analyze_aws_region,
                    analyze_aws_profile,
                ],
                outputs=[
                    analyze_status,
                    analyze_report_md,
                    analyze_json_dl,
                    analyze_html_dl,
                ],
            )

        # ---------------------------------------------------------------
        # Tab 3: Simulate
        # ---------------------------------------------------------------
        with gr.TabItem("Simulate"):
            gr.Markdown("## Attack simulation against agent spec")

            with gr.Row():
                with gr.Column():
                    sim_spec = gr.File(
                        label="Upload agent_spec.yaml",
                        file_types=[".yaml", ".yml"],
                    )
                    sim_attack_api = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        value="openai",
                        label="Attack API",
                    )
                    sim_attack_model = gr.Textbox(
                        label="Attack Model",
                        value="gpt-4o",
                    )
                    sim_judge_api = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        value="openai",
                        label="Judge API",
                    )
                    sim_judge_model = gr.Textbox(
                        label="Judge Model",
                        value="gpt-4o",
                    )
                    sim_categories = gr.CheckboxGroup(
                        [
                            "prompt_injection",
                            "jailbreak",
                            "data_exfiltration",
                            "privilege_escalation",
                            "tool_misuse",
                        ],
                        label="Categories (optional)",
                    )
                    sim_layers = gr.CheckboxGroup(
                        ["prompt", "tool", "architecture"],
                        label="Target Layers (optional)",
                    )
                    sim_separator = gr.Textbox(
                        label="Separator (optional)",
                        placeholder="e.g., ---",
                    )
                    sim_aws_region = gr.Textbox(
                        label="AWS Region (optional)",
                        placeholder="e.g., us-east-1",
                    )
                    sim_aws_profile = gr.Textbox(
                        label="AWS Profile (optional)",
                        placeholder="e.g., default",
                    )

                with gr.Column():
                    sim_run_btn = gr.Button("Run Simulation", variant="primary")
                    sim_status = gr.Textbox(label="Status")
                    sim_report_md = gr.Markdown(label="Report")
                    sim_json_dl = gr.File(label="Download JSON")
                    sim_html_dl = gr.File(label="Download HTML")

            sim_run_btn.click(
                run_simulate_webui,
                inputs=[
                    sim_spec,
                    sim_attack_api,
                    sim_attack_model,
                    sim_judge_api,
                    sim_judge_model,
                    sim_categories,
                    sim_layers,
                    sim_separator,
                    sim_aws_region,
                    sim_aws_profile,
                ],
                outputs=[
                    sim_status,
                    sim_report_md,
                    sim_json_dl,
                    sim_html_dl,
                ],
            )

        # ---------------------------------------------------------------
        # Tab 4: Remediate
        # ---------------------------------------------------------------
        with gr.TabItem("Remediate"):
            gr.Markdown("## Layer-by-layer remediation of agent spec")

            with gr.Row():
                with gr.Column():
                    rem_spec = gr.File(
                        label="Upload agent_spec.yaml",
                        file_types=[".yaml", ".yml"],
                    )
                    rem_layers = gr.CheckboxGroup(
                        ["prompt", "tool", "architecture"],
                        label="Target Layers (optional)",
                    )
                    rem_eval_api = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        value="openai",
                        label="Eval API",
                    )
                    rem_eval_model = gr.Textbox(
                        label="Eval Model",
                        value="gpt-4o",
                    )
                    rem_iterations = gr.Slider(
                        1, 10, value=3, step=1,
                        label="Max Iterations",
                    )
                    rem_threshold = gr.Slider(
                        0, 10, value=8.5, step=0.1,
                        label="Satisfaction Threshold",
                    )
                    rem_techniques = gr.CheckboxGroup(
                        [
                            "spotlighting",
                            "random_sequence_enclosure",
                            "instruction_defense",
                            "role_consistency",
                            "secrets_exclusion",
                        ],
                        label="Techniques (optional)",
                    )
                    rem_aws_region = gr.Textbox(
                        label="AWS Region (optional)",
                        placeholder="e.g., us-east-1",
                    )
                    rem_aws_profile = gr.Textbox(
                        label="AWS Profile (optional)",
                        placeholder="e.g., default",
                    )

                with gr.Column():
                    rem_run_btn = gr.Button("Run Remediation", variant="primary")
                    rem_status = gr.Textbox(label="Status")
                    rem_report_md = gr.Markdown(label="Report")
                    rem_json_dl = gr.File(label="Download JSON")
                    rem_html_dl = gr.File(label="Download HTML")
                    rem_spec_dl = gr.File(label="Download Improved agent_spec.yaml")

            rem_run_btn.click(
                run_remediate_webui,
                inputs=[
                    rem_spec,
                    rem_layers,
                    rem_eval_api,
                    rem_eval_model,
                    rem_iterations,
                    rem_threshold,
                    rem_techniques,
                    rem_aws_region,
                    rem_aws_profile,
                ],
                outputs=[
                    rem_status,
                    rem_report_md,
                    rem_json_dl,
                    rem_html_dl,
                    rem_spec_dl,
                ],
            )

        # ---------------------------------------------------------------
        # Tab 5: Report
        # ---------------------------------------------------------------
        with gr.TabItem("Report"):
            gr.Markdown("## Convert JSON results to formatted reports")

            with gr.Row():
                with gr.Column():
                    report_file = gr.File(
                        label="Upload JSON Results",
                        file_types=[".json"],
                    )
                    report_format = gr.Radio(
                        ["markdown", "html", "json"],
                        value="markdown",
                        label="Output Format",
                    )

                with gr.Column():
                    report_run_btn = gr.Button("Generate Report", variant="primary")
                    report_status = gr.Textbox(label="Status")
                    report_preview_md = gr.Markdown(label="Preview")
                    report_download = gr.File(label="Download Report")

            report_run_btn.click(
                run_report_webui,
                inputs=[report_file, report_format],
                outputs=[report_status, report_preview_md, report_download],
            )

        # ---------------------------------------------------------------
        # Tab 6: Diff
        # ---------------------------------------------------------------
        with gr.TabItem("Diff"):
            gr.Markdown("## Compare two agent_spec.yaml files")

            with gr.Row():
                with gr.Column():
                    diff_before = gr.File(
                        label="Before (agent_spec.yaml)",
                        file_types=[".yaml", ".yml"],
                    )
                    diff_after = gr.File(
                        label="After (agent_spec.yaml)",
                        file_types=[".yaml", ".yml"],
                    )

                with gr.Column():
                    diff_run_btn = gr.Button("Run Diff", variant="primary")
                    diff_status = gr.Textbox(label="Status")
                    diff_result_md = gr.Markdown(label="Diff Result")

            diff_run_btn.click(
                run_diff_webui,
                inputs=[diff_before, diff_after],
                outputs=[diff_status, diff_result_md],
            )

        # ---------------------------------------------------------------
        # Tab 7: Evaluate (Legacy)
        # ---------------------------------------------------------------
        with gr.TabItem("Evaluate (Legacy)"):
            gr.Markdown("## Evaluate the security of your prompt")

            with gr.Row():
                with gr.Column():
                    eval_input_mode = gr.Radio(
                        ["chat", "completion"],
                        value="chat",
                        label="Input Mode",
                        info="Select 'chat' for role-based messages or 'completion' for single prompt strings.",
                    )
                    eval_input_format = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        value="openai",
                        label="Input Format",
                        info="Select the format of the input prompt (e.g., OpenAI, Claude, or Bedrock).",
                    )
                    eval_prompt = gr.Textbox(
                        label="Prompt",
                        lines=12,
                        placeholder=(
                            "For 'chat' mode and 'openai' format, provide JSON like:\n"
                            '{"messages": [{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": "Hello!"}]}\n\n'
                            "For 'chat' mode and 'claude' format, provide JSON like:\n"
                            '{"system": "You are a helpful assistant.", "messages": [{"role": "user", "content": "Hello!"}]}\n\n'
                            "For 'chat' mode and 'bedrock' format, provide JSON like:\n"
                            '{"system": "You are a helpful assistant.", "messages": [{"role": "user", "content": [{"text": "Hello!"}]}]}\n\n'
                            "For 'completion' mode, provide plain text like:\n"
                            "You are a helpful assistant. Please answer the user's questions."
                        ),
                    )
                    legacy_eval_api_mode = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        value="openai",
                        label="Evaluation API Mode",
                    )
                    legacy_eval_model = gr.Textbox(label="Evaluation Model", value="gpt-4o")
                    eval_aws_region = gr.Textbox(
                        label="AWS Region (optional, for bedrock api mode)",
                        value="us-east-1",
                        placeholder="e.g., us-east-1",
                    )
                    eval_aws_profile = gr.Textbox(
                        label="AWS Profile (optional, for bedrock api mode)",
                        placeholder="e.g., default, my-profile",
                    )
                    eval_description = gr.Textbox(label="User Input Description")
                    eval_techniques = gr.CheckboxGroup(
                        [
                            "spotlighting",
                            "random_sequence_enclosure",
                            "instruction_defense",
                            "role_consistency",
                            "secrets_exclusion",
                        ],
                        label="Evaluation Techniques",
                        info="Select which security techniques to evaluate. If none selected, all will be used.",
                    )

                with gr.Column():
                    eval_run_button = gr.Button("Run Evaluation", variant="primary")
                    eval_status = gr.Textbox(label="Status")
                    eval_output = gr.Textbox(
                        label="Evaluation Output",
                        lines=15,
                        max_lines=30,
                    )
                    eval_download = gr.File(label="Download Evaluation Results (JSON)")
                    eval_html_download = gr.File(
                        label="Download Evaluation Report (HTML)"
                    )

            eval_run_button.click(
                run_evaluation,
                inputs=[
                    eval_prompt,
                    eval_input_mode,
                    eval_input_format,
                    legacy_eval_api_mode,
                    legacy_eval_model,
                    eval_description,
                    eval_techniques,
                    eval_aws_region,
                    eval_aws_profile,
                ],
                outputs=[eval_status, eval_output, eval_download, eval_html_download],
            )

        # ---------------------------------------------------------------
        # Tab 8: Improve (Legacy)
        # ---------------------------------------------------------------
        with gr.TabItem("Improve (Legacy)"):
            gr.Markdown("## Improve the security of your prompt")

            with gr.Row():
                with gr.Column():
                    input_mode = gr.Radio(
                        ["chat", "completion"],
                        value="chat",
                        label="Input Mode",
                        info="Select 'chat' for role-based messages or 'completion' for single prompt strings.",
                    )
                    input_format = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        value="openai",
                        label="Input Format",
                        info="Select the format of the input prompt (e.g., OpenAI, Claude, or Bedrock).",
                    )
                    prompt = gr.Textbox(
                        label="Prompt",
                        lines=12,
                        placeholder=(
                            "For 'chat' mode and 'openai' format, provide JSON like:\n"
                            '{"messages": [{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": "Hello!"}]}\n\n'
                            "For 'chat' mode and 'claude' format, provide JSON like:\n"
                            '{"system": "You are a helpful assistant.", "messages": [{"role": "user", "content": "Hello!"}]}\n\n'
                            "For 'chat' mode and 'bedrock' format, provide JSON like:\n"
                            '{"system": "You are a helpful assistant.", "messages": [{"role": "user", "content": [{"text": "Hello!"}]}]}\n\n'
                            "For 'completion' mode, provide plain text like:\n"
                            "You are a helpful assistant. Please answer the user's questions."
                        ),
                    )
                    improve_eval_api_mode = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        value="openai",
                        label="Evaluation API Mode",
                    )
                    improve_eval_model = gr.Textbox(label="Evaluation Model", value="gpt-4o")
                    attack_api_mode = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        value="openai",
                        label="Attack API Mode",
                    )
                    attack_model = gr.Textbox(label="Attack Model (optional)")
                    judge_api_mode = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        value="openai",
                        label="Judge API Mode",
                    )
                    judge_model = gr.Textbox(label="Judge Model (optional)")
                    aws_region = gr.Textbox(
                        label="AWS Region (optional, for bedrock api mode)",
                        value="us-east-1",
                        placeholder="e.g., us-east-1",
                    )
                    aws_profile = gr.Textbox(
                        label="AWS Profile (optional, for bedrock api mode)",
                        placeholder="e.g., default, my-profile",
                    )
                    description = gr.Textbox(label="User Input Description")
                    iterations = gr.Slider(
                        1, 10, value=3, step=1, label="Max Iterations"
                    )
                    threshold = gr.Slider(
                        0, 10, value=8.5, step=0.1, label="Satisfaction Threshold"
                    )
                    techniques = gr.CheckboxGroup(
                        [
                            "spotlighting",
                            "random_sequence_enclosure",
                            "instruction_defense",
                            "role_consistency",
                            "secrets_exclusion",
                        ],
                        label="Defense Techniques",
                    )
                    test = gr.Checkbox(label="Run Injection Test", value=False)
                    separator = gr.Textbox(label="Attack Separator", value="")
                    tools_json = gr.Textbox(label="Tools (JSON)", lines=4)
                with gr.Column():
                    run_button = gr.Button("Run Improvement", variant="primary")
                    result = gr.Textbox(label="Status")
                    download_html = gr.File(label="Download Report HTML")
                    download_json = gr.File(label="Download Attack Results JSON")

            run_button.click(
                run_improvement,
                inputs=[
                    prompt,
                    input_mode,
                    input_format,
                    improve_eval_api_mode,
                    improve_eval_model,
                    attack_api_mode,
                    attack_model,
                    judge_api_mode,
                    judge_model,
                    description,
                    iterations,
                    threshold,
                    techniques,
                    test,
                    separator,
                    tools_json,
                    aws_region,
                    aws_profile,
                ],
                outputs=[result, download_html, download_json],
            )


def launch_webui():
    demo.launch()
