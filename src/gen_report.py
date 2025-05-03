import os
import html
import json
import random
import string


def generate_report(
    initial_prompt,
    initial_evaluation,
    final_prompt,
    final_evaluation,
    attack_results,
    output_dir_path,
    initial_avg_score,
    final_avg_score,
):
    base = os.path.join(output_dir_path, "prompt_security_report")
    rand_suffix = "".join(random.choices(string.ascii_letters + string.digits, k=10))
    html_path = f"{base}_{rand_suffix}.html"
    json_path = f"{base}_{rand_suffix}_attack_results.json"

    generate_html_report(
        initial_prompt,
        initial_evaluation,
        final_prompt,
        final_evaluation,
        attack_results,
        html_path,
        json_path,
        initial_avg_score,
        final_avg_score,
    )

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(attack_results, f, indent=2, ensure_ascii=False)


def generate_html_report(
    initial_prompt,
    initial_evaluation,
    final_prompt,
    final_evaluation,
    attack_results,
    html_path,
    json_path,
    initial_score,
    final_score,
):
    html_content = build_html_content(
        initial_prompt,
        initial_evaluation,
        final_prompt,
        final_evaluation,
        attack_results,
        json_path,
        initial_score,
        final_score,
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def build_html_content(
    initial_prompt,
    initial_evaluation,
    final_prompt,
    final_evaluation,
    attack_results,
    json_path,
    initial_score,
    final_score,
):
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
            summary {{
                cursor: pointer;
                font-weight: bold;
            }}
            .download-btn {{
                display: inline-block;
                margin-top: 10px;
                padding: 8px 12px;
                background-color: #28a745;
                color: white;
                border-radius: 4px;
                text-decoration: none;
            }}
        </style>
    </head>
    <body>
        <h1>Prompt Security Evaluation Report</h1>
        <div class="section">
            <h2>Initial Prompt</h2>
            <p>This is the original prompt before any improvements were applied.</p>
            <pre>{escape_html(initial_prompt)}</pre>
        </div>
        <div class="section">
            <h2>Initial Evaluation</h2>
            <p>Evaluation of the initial prompt on various security categories and subcategories.</p>
            <p><strong>Average Satisfaction Score (0-10): {initial_score} </strong></p>
            {format_evaluation_table(initial_evaluation)}
        </div>
        <div class="section">
            <h2>Final Prompt</h2>
            <p>This is the improved version of the prompt after refinement.</p>
            <pre>{escape_html(final_prompt)}</pre>
        </div>
        <div class="section">
            <h2>Final Evaluation</h2>
            <p>Evaluation of the final prompt after refinement.</p>
            <p><strong>Average Satisfaction Score (0-10): {final_score} </strong></p>
            {format_evaluation_table(final_evaluation)}
        </div>
        <div class="section">
            <h2>Injection Test Results</h2>
            <p>Automated test results showing whether the prompt resisted different types of prompt injection attacks.</p>
            <p><strong>{passed} / {total} PASSED</strong> — PASSED = attack blocked, FAILED = attack succeeded.</p>
            {format_attack_table(attack_results)}
            <a class="download-btn" href="{os.path.basename(json_path)}" download>Download Raw Attack Test JSON</a>
        </div>
    </body>
    </html>
    """


def escape_html(text):
    return html.escape(text)


def format_dict(d):
    from pprint import pformat

    return pformat(d)


def format_evaluation_table(evaluation):
    rows = ""
    for category, detail in evaluation.items():
        if category in ("critique", "recommendation"):
            continue
        for subcategory, scores in detail.items():
            rows += f"<tr><td>{escape_html(category)}</td><td>{escape_html(subcategory)}</td><td>{scores['satisfaction']}</td><td>{scores['mark']}</td><td>{escape_html(scores['comment'])}</td></tr>"
    return f"<table><tr><th>Category</th><th>Subcategory</th><th>Score</th><th>Mark</th><th>Comment</th></tr>{rows}</table>"


def format_attack_table(results):
    rows = ""
    for r in results:
        rows += f"<tr><td>{escape_html(r.get('category', '-'))}</td><td>{escape_html(r['attack'])}</td><td>{escape_html(r['result'])}</td><td>{'✅' if not r['success'] else '❌'}</td></tr>"
    return f"<table><tr><th>Category</th><th>Attack</th><th>Response</th><th>Result</th></tr>{rows}</table>"
