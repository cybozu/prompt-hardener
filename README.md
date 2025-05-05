# 🔐 Prompt Hardener
<img width="300" alt="prompt-hardener-logo" src="https://github.com/user-attachments/assets/f2a6d1eb-f733-419a-9e2c-d0f0ccbe6049">

Prompt Hardener is an open-source tool that **evaluates and strengthens system prompts** used in LLM-based applications. It helps developers proactively defend against **prompt injection attacks** by combining automated evaluation, self-refinement, and attack simulation — all exportable as structured reports.

Originally created to help secure LLM agents like chatbots, RAG systems, and tool-augmented assistants, Prompt Hardener is designed to be **usable, extensible, and integrable** in real-world development workflows.

> 📌 Designed for:  
> - LLM application developers  
> - Security engineers working on AI pipelines  
> - Prompt engineers and red teamers  

## ✨ Features

| Feature | Description |
|--------|-------------|
| 🧠 Self-refinement | Iteratively improves prompts based on security evaluation feedback |
| 🛡️ Hardening Techniques | Apply strategies like Spotlighting, Signed Prompt, and Rule Reinforcement |
| 💣 Automated Attack Testing | Runs prompt injection payloads across multiple categories |
| 📊 HTML Reports | Clear, styled summaries of evaluations and attack outcomes |
| 📁 JSON Output | Raw data for CI/CD integration or manual inspection |
| 🌐 Web UI | Use with Gradio for demos, experimentation, and quick prototyping |
| 🔌 Extensible | Easily define new attack vectors or refine strategies via code/config |

## 🚀 Getting Started
### 🔧 Installation

```bash
git clone https://github.com/cybozu/prompt-hardener.git
cd prompt-hardener
pip install -r requirements.txt
```

### 🖥️ CLI Usage
Here is an example of command using cli mode.

```bash
python3 src/main.py \
  -t prompt.txt \
  -am openai \
  -m gpt-4o-mini \
  -o out.txt \
  --test-after \
  --test-model gpt-4o-mini \
  --report-dir reports/
```

<details>
<summary>Arguments Overview</summary>

| Argument                   | Short | Type        | Required | Default           | Description                                                                                                              |
| -------------------------- | ----- | ----------- | -------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `--target-prompt-path`     | `-t`  | `str`       | ✅ Yes    | -                 | Path to the file containing the target system prompt                                                                     |
| `--api-mode`               | `-am` | `str`       | ✅ Yes    | -                 | API mode to use: `"openai"`                                                                         |
| `--model`                  | `-m`  | `str`       | ✅ Yes    | -                 | Model name to use (e.g., `"gpt-4"`)                                                                          |
| `--user-input-description` | `-ui` | `str`       | ❌ No     | `None`            | Description of expected user inputs (used for better evaluation)                                                         |
| `--output-path`            | `-o`  | `str`       | ✅ Yes    | -                 | Output path to save the improved prompt                                                                                  |
| `--max-iterations`         | `-n`  | `int`       | ❌ No     | `3`               | Maximum number of self-refinement iterations                                                                             |
| `--threshold`              |       | `float`     | ❌ No     | `8.5`             | Satisfaction score threshold (0–10) to stop refinement early                                                             |
| `--apply-techniques`       |       | `list[str]` | ❌ No     | All techniques    | Defense techniques to apply:<br>• `spotlighting`<br>• `signed_prompt`<br>• `rule_reinforcement`<br>• `structured_output` |
| `--test-after`             |       | `flag`      | ❌ No     | `False`           | Run automated injection test after final prompt is generated                                                             |
| `--test-model`             |       | `str`       | ❌ No     | `"gpt-3.5-turbo"` | Model used to simulate attacks during post-testing                                                                       |
| `--test-separator`         |       | `str`       | ❌ No     | `None`            | Prefix (e.g., `###`) to prepend before attack payload in the test                                                        |
| `--tools-path`             |       | `str`       | ❌ No     | `None`            | Path to JSON defining available tools for LLMs (function calling context)                                                |
| `--report-dir`             |       | `str`       | ❌ No     | `None`            | Output directory for report files (HTML and JSON)                                                                        |

</details>

### 🌐 Web UI (Gradio)

```bash
python3 src/webui.py
```

Then visit http://localhost:7860 to use Prompt Hardener interactively:
- Paste prompts
- Choose models & settings
- Download hardened prompt and reports

Perfect for demoing, auditing, or collaborating across teams.

## 🧪 Attack Simulation

Prompt Hardener includes **automated adversarial testing** after hardening.

Supported categories (extensible):
- Persona Switching
- Output Attack
- Prompt Leaking
- Chain-of-Thought Escape
- Function Call Hijacking
- Ignoring RAG Instructions
- Privilege Escalation
- JSON/Structured Output Hijacking
- Tool Definition Leaking

Each attack is automatically injected and measured for:
- Injection attacks blocked (✅ or ❌)
- LLM response contents
- Category, payload, and result

## 🛠️ Hardening Techniques

Prompt Hardener includes multiple defense strategies:

| Technique              | Description                                                     |
| ---------------------- | --------------------------------------------------------------- |
| **Spotlighting**       | Emphasizes instruction boundaries and user roles explicitly     |
| **Signed Prompt**      | Embeds cryptographic or structural markers to prevent tampering |
| **Rule Reinforcement** | Repeats constraints or refusals clearly within context          |
| **Structured Output**  | Encourages consistent, parseable LLM responses                  |

## 📄 Reporting

After each run, Prompt Hardener generates:

- `prompt_security_report_<random value>.html`:
  - Visual report of improved prompt, evaluations and injection test results
- `prompt_security_report_<random value>_attack_results.json:`:
  - Raw structured data of injection test results

Reports are styled for readability and highlight:
- Initial vs. final prompts
- Evaluation category-wise scores and comments
- Injection attack blocked stats (e.g. 12/15 PASSED)
  - PASSED = attack blocked, FAILED = attack succeeded.