import gradio as gr
import os
import tempfile
import shutil
import sys
from pathlib import Path
from main import main as cli_main


def run_evaluation(
    prompt,
    api_mode,
    model,
    description,
    iterations,
    threshold,
    techniques,
    test,
    test_model,
    separator,
    tools_json,
):
    report_dir = Path(tempfile.mkdtemp())
    report_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        prompt_path = Path(tmpdir) / "prompt.txt"
        output_path = Path(tmpdir) / "out.txt"
        tools_path = None

        prompt_path.write_text(prompt, encoding="utf-8")
        if tools_json:
            tools_path = Path(tmpdir) / "tools.json"
            tools_path.write_text(tools_json, encoding="utf-8")

        sys.argv = [
            "main.py",
            "-t",
            str(prompt_path),
            "-am",
            api_mode,
            "-m",
            model,
            "-o",
            str(output_path),
            "-n",
            str(iterations),
            "--threshold",
            str(threshold),
            "--report-dir",
            str(report_dir),
        ]
        if description:
            sys.argv += ["-ui", description]
        if techniques:
            sys.argv += ["--apply-techniques"] + techniques
        if test:
            sys.argv += ["--test-after", "--test-model", test_model]
        if separator:
            sys.argv += ["--test-separator", separator]
        if tools_path:
            sys.argv += ["--tools-path", str(tools_path)]

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
    gr.Markdown("# 🔐 Prompt Hardener")
    with gr.Row():
        with gr.Column():
            prompt = gr.Textbox(label="System Prompt", lines=12)
            api_mode = gr.Radio(["openai", "ollama"], value="openai", label="API Mode")
            model = gr.Textbox(label="Model", value="gpt-4")
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
            test_model = gr.Textbox(label="Test Model", value="gpt-3.5-turbo")
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
            api_mode,
            model,
            description,
            iterations,
            threshold,
            techniques,
            test,
            test_model,
            separator,
            tools_json,
        ],
        outputs=[result, download_html, download_json],
    )

demo.launch()
