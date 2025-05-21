import gradio as gr
import tempfile
import shutil
import sys
from pathlib import Path
from main import main as cli_main


def run_evaluation(
    prompt,
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

        sys.argv = [
            "main.py",
            "--target-prompt-path",
            str(prompt_path),
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
            sys.argv += ["--user-input-description", description]
        if techniques:
            sys.argv += ["--apply-techniques"] + techniques
        if test:
            if attack_api_mode:
                sys.argv += ["--attack-api-mode", attack_api_mode]
            if attack_model:
                sys.argv += ["--attack-model", attack_model]
            if judge_api_mode:
                sys.argv += ["--judge-api-mode", judge_api_mode]
            if judge_model:
                sys.argv += ["--judge-model", judge_model]
            sys.argv += ["--test-after"]
        if separator:
            sys.argv += ["--test-separator", separator]
        if tools_path:
            sys.argv += ["--tools-path", str(tools_path)]
        if aws_region:
            sys.argv += ["--aws-region", aws_region]

        cli_main()

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
            return "✅ Complete", html_tmp.name, json_tmp.name
        else:
            return "⚠️ Report generation failed", "", ""


# Gradio UI
with gr.Blocks() as demo:
    gr.Markdown("# 🔐 Prompt Hardener Web UI")

    with gr.Row():
        with gr.Column():
            prompt = gr.Textbox(
                label="System Prompt (Chat Completion Format)", lines=12
            )
            eval_api_mode = gr.Radio(
                ["openai", "claude", "bedrock"], value="openai", label="Evaluation API Mode"
            )
            eval_model = gr.Textbox(label="Evaluation Model", value="gpt-4o")
            attack_api_mode = gr.Radio(
                ["openai", "claude", "bedrock"], value="openai", label="Attack API Mode"
            )
            attack_model = gr.Textbox(label="Attack Model (optional)")
            judge_api_mode = gr.Radio(
                ["openai", "claude", "bedrock"], value="openai", label="Judge API Mode"
            )
            judge_model = gr.Textbox(label="Judge Model (optional)")
            aws_region = gr.Textbox(
                label="AWS Region (optional, for bedrock api mode)",
                value="us-east-1",
                placeholder="e.g., us-east-1",
            )
            description = gr.Textbox(label="User Input Description")
            iterations = gr.Slider(1, 10, value=3, step=1, label="Max Iterations")
            threshold = gr.Slider(
                0, 10, value=8.5, step=0.1, label="Satisfaction Threshold"
            )
            techniques = gr.CheckboxGroup(
                [
                    "spotlighting",
                    "signed_prompt",
                    "rule_reinforcement",
                    "structured_output",
                ],
                label="Defense Techniques",
            )
            test = gr.Checkbox(label="Run Injection Test", value=True)
            separator = gr.Textbox(label="Attack Separator", value="")
            tools_json = gr.Textbox(label="Tools (JSON)", lines=4)
        with gr.Column():
            run_button = gr.Button("Run Evaluation")
            result = gr.Textbox(label="Status")
            download_html = gr.File(label="Download Report HTML")
            download_json = gr.File(label="Download Attack Results JSON")

    run_button.click(
        run_evaluation,
        inputs=[
            prompt,
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
        ],
        outputs=[result, download_html, download_json],
    )

demo.launch()
