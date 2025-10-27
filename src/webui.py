import gradio as gr
import tempfile
import shutil
import sys
import subprocess
from pathlib import Path


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


# Gradio UI
with gr.Blocks() as demo:
    gr.Markdown("# 🔐 Prompt Hardener Web UI")

    with gr.Tabs():
        # Evaluate Tab
        with gr.TabItem("🧪 Evaluate"):
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
                    eval_api_mode = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        value="openai",
                        label="Evaluation API Mode",
                    )
                    eval_model = gr.Textbox(label="Evaluation Model", value="gpt-4o")
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
                    eval_run_button = gr.Button("🧪 Run Evaluation", variant="primary")
                    eval_status = gr.Textbox(label="Status")
                    eval_output = gr.Textbox(
                        label="Evaluation Output",
                        lines=15,
                        max_lines=30,
                        show_copy_button=True,
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
                    eval_api_mode,
                    eval_model,
                    eval_description,
                    eval_techniques,
                    eval_aws_region,
                    eval_aws_profile,
                ],
                outputs=[eval_status, eval_output, eval_download, eval_html_download],
            )

        # Improve Tab
        with gr.TabItem("🚀 Improve"):
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
                    eval_api_mode = gr.Radio(
                        ["openai", "claude", "bedrock"],
                        value="openai",
                        label="Evaluation API Mode",
                    )
                    eval_model = gr.Textbox(label="Evaluation Model", value="gpt-4o")
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
                    run_button = gr.Button("🚀 Run Improvement", variant="primary")
                    result = gr.Textbox(label="Status")
                    download_html = gr.File(label="Download Report HTML")
                    download_json = gr.File(label="Download Attack Results JSON")

            run_button.click(
                run_improvement,
                inputs=[
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
                ],
                outputs=[result, download_html, download_json],
            )


def launch_webui():
    demo.launch()
