from typing import List, Dict, Any
import os
import html
import json
import random
import string
from schema import PromptInput
from prompt import show_prompt


def generate_improvement_report(
    initial_prompt: PromptInput,
    initial_evaluation: Dict[str, Any],
    final_prompt: PromptInput,
    final_evaluation: Dict[str, Any],
    attack_results: List[Dict[str, Any]],
    output_dir_path: str,
    initial_avg_score: float,
    final_avg_score: float,
    eval_model: str,
    attack_model: str,
    judge_model: str,
    eval_api_mode: str,
    attack_api_mode: str,
    judge_api_mode: str,
) -> None:
    os.makedirs(output_dir_path, exist_ok=True)
    base = os.path.join(output_dir_path, "prompt_security_report")
    rand_suffix = "".join(random.choices(string.ascii_letters + string.digits, k=10))
    html_path = f"{base}_{rand_suffix}.html"
    json_path = f"{base}_{rand_suffix}_attack_results.json"

    generate_improvement_html_report(
        initial_prompt,
        initial_evaluation,
        final_prompt,
        final_evaluation,
        attack_results,
        html_path,
        json_path,
        initial_avg_score,
        final_avg_score,
        eval_model,
        attack_model,
        judge_model,
        eval_api_mode,
        attack_api_mode,
        judge_api_mode,
    )

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(attack_results, f, indent=2, ensure_ascii=False)


def generate_evaluation_report(
    prompt: PromptInput,
    evaluation: Dict[str, Any],
    output_dir_path: str,
    avg_score: float,
    eval_model: str,
    eval_api_mode: str,
) -> None:
    """Generate a report specifically for evaluation results without improvement or attacks."""
    os.makedirs(output_dir_path, exist_ok=True)
    base = os.path.join(output_dir_path, "prompt_evaluation_report")
    rand_suffix = "".join(random.choices(string.ascii_letters + string.digits, k=10))
    html_path = f"{base}_{rand_suffix}.html"

    generate_evaluation_html_report(
        prompt,
        evaluation,
        html_path,
        avg_score,
        eval_model,
        eval_api_mode,
    )


def generate_improvement_html_report(
    initial_prompt: PromptInput,
    initial_evaluation: Dict[str, Any],
    final_prompt: PromptInput,
    final_evaluation: Dict[str, Any],
    attack_results: List[Dict[str, Any]],
    html_path: str,
    json_path: str,
    initial_score: float,
    final_score: float,
    eval_model: str,
    attack_model: str,
    judge_model: str,
    eval_api_mode: str,
    attack_api_mode: str,
    judge_api_mode: str,
) -> None:
    html_content = build_improvement_html_content(
        initial_prompt,
        initial_evaluation,
        final_prompt,
        final_evaluation,
        attack_results,
        json_path,
        initial_score,
        final_score,
        eval_model,
        attack_model,
        judge_model,
        eval_api_mode,
        attack_api_mode,
        judge_api_mode,
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_evaluation_html_report(
    prompt: PromptInput,
    evaluation: Dict[str, Any],
    html_path: str,
    avg_score: float,
    eval_model: str,
    eval_api_mode: str,
) -> None:
    """Generate HTML report for evaluation results only."""
    html_content = build_evaluation_html_content(
        prompt,
        evaluation,
        avg_score,
        eval_model,
        eval_api_mode,
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def build_improvement_html_content(
    initial_prompt: PromptInput,
    initial_evaluation: Dict[str, Any],
    final_prompt: PromptInput,
    final_evaluation: Dict[str, Any],
    attack_results: List[Dict[str, Any]],
    json_path: str,
    initial_score: float,
    final_score: float,
    eval_model: str,
    attack_model: str,
    judge_model: str,
    eval_api_mode: str,
    attack_api_mode: str,
    judge_api_mode: str,
) -> str:
    total = len(attack_results)
    passed = len([r for r in attack_results if not r["success"]])

    return f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                padding: 30px;
                line-height: 1.6;
                color: #333;
                background-color: #fff;
            }}
            h1 {{
                background-color: #007acc;
                color: white;
                padding: 10px;
                border-radius: 5px;
            }}
            h2 {{
                color: #007acc;
                margin-top: 30px;
            }}
            pre {{
                background: #f4f4f4;
                padding: 10px;
                border-radius: 5px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
            .section {{
                margin-bottom: 40px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
            }}
            th {{
                background-color: #007acc;
                color: white;
            }}
        </style>
    </head>
    <body>
        <h1>Prompt Security Improvement Report</h1>
        <div class="section">
            <h2>LLM Configuration</h2>
            <table>
              <tr><th>Purpose</th><th>API</th><th>Model</th></tr>
              <tr><td>Evaluation & Improvement</td><td>{escape_html(eval_api_mode)}</td><td>{escape_html(eval_model)}</td></tr>
              <tr><td>Attack Execution</td><td>{escape_html(attack_api_mode)}</td><td>{escape_html(attack_model)}</td></tr>
              <tr><td>Injection Judgment</td><td>{escape_html(judge_api_mode)}</td><td>{escape_html(judge_model)}</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Initial Prompt</h2>
            <p>This is the original prompt before any improvements were applied.</p>
            <pre>{escape_html(show_prompt(initial_prompt))}</pre>
        </div>
        <div class="section">
            <h2>Initial Evaluation</h2>
            <p><strong>Average Satisfaction Score (0-10): {initial_score}</strong></p>
            {format_evaluation_table(initial_evaluation)}
        </div>
        <div class="section">
            <h2>Final Prompt</h2>
            <p>This is the improved version of the prompt after refinement.</p>
            <pre>{escape_html(show_prompt(final_prompt))}</pre>
        </div>
        <div class="section">
            <h2>Final Evaluation</h2>
            <p><strong>Average Satisfaction Score (0-10): {final_score}</strong></p>
            {format_evaluation_table(final_evaluation)}
        </div>
        <div class="section">
            <h2>Injection Test Results</h2>
            <p><strong>{passed} / {total} PASSED</strong> — PASSED = attack blocked, FAILED = attack succeeded.</p>
            {format_attack_table(attack_results)}
        </div>
    </body>
    </html>
    """


def escape_html(text: str) -> str:
    return html.escape(text)


def format_evaluation_table(evaluation: Dict[str, Any]) -> str:
    rows = ""
    for category, detail in evaluation.items():
        if category in ("critique", "recommendation"):
            continue
        for subcategory, scores in detail.items():
            rows += f"<tr><td>{escape_html(category)}</td><td>{escape_html(subcategory)}</td><td>{scores['satisfaction']}</td><td>{scores['mark']}</td><td>{escape_html(scores['comment'])}</td></tr>"
    return f"<table><tr><th>Category</th><th>Subcategory</th><th>Score</th><th>Mark</th><th>Comment</th></tr>{rows}</table>"


def format_attack_table(results: List[Dict[str, Any]]) -> str:
    rows = ""
    for r in results:
        rows += f"<tr><td>{escape_html(r.get('category', '-'))}</td><td>{escape_html(r['attack'])}</td><td>{escape_html(r['result'])}</td><td>{'✅' if not r['success'] else '❌'}</td></tr>"
    return f"<table><tr><th>Category</th><th>Attack</th><th>Response</th><th>Result</th></tr>{rows}</table>"


def build_evaluation_html_content(
    prompt: PromptInput,
    evaluation: Dict[str, Any],
    avg_score: float,
    eval_model: str,
    eval_api_mode: str,
) -> str:
    """Build HTML content for evaluation-only report."""
    return f"""
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                padding: 30px;
                line-height: 1.6;
                color: #333;
                background-color: #fff;
            }}
            h1 {{
                background-color: #007acc;
                color: white;
                padding: 10px;
                border-radius: 5px;
            }}
            h2 {{
                color: #007acc;
                margin-top: 30px;
            }}
            pre {{
                background: #f4f4f4;
                padding: 10px;
                border-radius: 5px;
                overflow-x: auto;
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
            .section {{
                margin-bottom: 40px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
            }}
            th {{
                background-color: #007acc;
                color: white;
            }}
            .score-summary {{
                background-color: #f0f8ff;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
                border-left: 4px solid #007acc;
            }}
        </style>
    </head>
    <body>
        <h1>Prompt Security Evaluation Report</h1>
        
        <div class="section">
            <h2>LLM Configuration</h2>
            <table>
              <tr><th>API</th><th>Model</th></tr>
              <tr><td>{escape_html(eval_api_mode)}</td><td>{escape_html(eval_model)}</td></tr>
            </table>
        </div>

        <div class="section">
            <h2>Evaluated Prompt</h2>
            <pre>{escape_html(show_prompt(prompt))}</pre>
        </div>
        
        <div class="score-summary">
            <h2>📊 Overall Evaluation Score</h2>
            <p><strong>Average Satisfaction Score: {avg_score}/10</strong></p>
            <p>This score represents the overall security posture of your prompt across all evaluated categories.</p>
        </div>
        
        <div class="section">
            <h2>Detailed Evaluation Results</h2>
            {format_evaluation_table(evaluation)}
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            {format_recommendations(evaluation)}
        </div>
    </body>
    </html>
    """


def format_recommendations(evaluation: Dict[str, Any]) -> str:
    """Format the recommendations section for evaluation report."""
    recommendations = evaluation.get("recommendation", "")
    critique = evaluation.get("critique", "")
    
    html = ""
    if critique:
        html += f"<h3>Overall Critique</h3><pre>{escape_html(critique)}</pre>"
    
    if recommendations:
        html += f"<h3>Improvement Recommendations</h3><pre>{escape_html(recommendations)}</pre>"
    
    if not html:
        html = "<p>No specific recommendations available.</p>"
    
    return html
