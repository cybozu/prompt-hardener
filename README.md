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

## 🚀 Getting Started
### 🔑 Set Up API Keys
Prompt Hardener uses LLMs to **evaluate** prompts, **apply security improvements**, **test prompt injection attacks**, and **judge whether attacks were successful** — all in an automated pipeline.

Prompt Hardener supports **OpenAI**, **Anthropic Claude** and **AWS Bedrock(only claude v3 or newer model)** APIs.

You must set at least one of the following environment variables before use:

```bash
# For OpenAI API (e.g., GPT-4, GPT-4o)
export OPENAI_API_KEY=...

# For Claude API (e.g., Claude 3.7 Sonnet)
export ANTHROPIC_API_KEY=...

# For Bedrock API (e.g., anthropic.claude-3-5-sonnet-20240620-v1:0)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
```

You can add these lines to your shell profile (e.g., `.bashrc`, `.zshrc`) to make them persistent.

### 🔧 Installation

```bash
git clone https://github.com/cybozu/prompt-hardener.git
cd prompt-hardener
pip install -e . -r requirements.txt
```

### 🖥️ CLI Usage
Here is an example of command using cli mode.

```bash
prompt-hardener improve \
  --input-mode chat \
  --input-format openai \
  --target-prompt-path path/to/prompt.json \
  --eval-api-mode openai \
  --eval-model gpt-4o-mini \
  --output-path path/to/hardened.json \
  --user-input-description Comments \
  --max-iterations 3 \
  --test-after \
  --report-dir ~/Downloads
```

<details>
<summary>Arguments Overview</summary>

| Argument                   | Short | Type        | Required | Default             | Description                                                                                                              |
| -------------------------- | ----- | ----------- | -------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `--target-prompt-path`     | `-t`  | `str`       | ✅ Yes    | -                   | Path to the file containing the target system prompt (Chat Completion message format, JSON).                             |
| `--input-mode`             |       | `str`       | ❌ No     | `chat`              | Prompt format type: `chat` for role-based messages, `completion` for single prompt string.                               |
| `--input-format`           |       | `str`       | ❌ No     | `openai`            | Input message format to parse: `openai`, `claude`, or `bedrock`.                                                         |
| `--eval-api-mode`          | `-ea` | `str`       | ✅ Yes    | -                   | LLM API used for evaluation and improvement (`openai`, `claude` or `bedrock`).                                           |
| `--eval-model`             | `-em` | `str`       | ✅ Yes    | -                   | Model name used for evaluation and improvement (e.g., `gpt-4o-mini`, `claude-3-7-sonnet-latest`, `anthropic.claude-3-5-sonnet-20240620-v1:0`).                        |
| `--attack-api-mode`        | `-aa` | `str`       | ❌ No     | `--eval-api-mode`   | LLM API used for executing attacks (defaults to the evaluation API).                                                     |
| `--attack-model`           | `-am` | `str`       | ❌ No     | `--eval-model`      | Model used to generate and run attacks (defaults to the evaluation model).                                               |
| `--judge-api-mode`         | `-ja` | `str`       | ❌ No     | `--eval-api-mode`   | LLM API used for attack insertion and success judgment (defaults to the attack API).                                     |
| `--judge-model`            | `-jm` | `str`       | ❌ No     | `--eval-model`      | Model used to insert attack payloads and judge injection success (defaults to the attack model).                         |
| `--aws-region`             | `-ar` | `str`       | ❌ No     | `us-east-1`         | AWS region for Bedrock API mode. Default is `us-east-1`.                                                                 |
| `--user-input-description` | `-ui` | `str`       | ❌ No     | `None`              | Description of user input fields (e.g., `Comments`), used to guide placement and tagging of user data.                   |
| `--output-path`            | `-o`  | `str`       | ✅ Yes    | -                   | File path to write the final improved prompt as JSON.                                                                    |
| `--max-iterations`         | `-n`  | `int`       | ❌ No     | `3`                 | Maximum number of improvement iterations.                                                                                |
| `--threshold`              |       | `float`     | ❌ No     | `8.5`               | Satisfaction score threshold (0–10) to stop refinement early if reached.                                                 |
| `--apply-techniques`       | `-a`  | `list[str]` | ❌ No     | All techniques      | Defense techniques to apply:<br>• `spotlighting`                                                                         |
| `--test-after`             | `-ta` | `flag`      | ❌ No     | `False`             | If set, runs a prompt injection test using various attack payloads after prompt improvement.                             |
| `--test-separator`         | `-ts` | `str`       | ❌ No     | `None`              | Optional string to prepend to each attack payload during injection testing (e.g., `\\n`, `###`).                         |
| `--tools-path`             | `-tp` | `str`       | ❌ No     | `None`              | Path to JSON file defining available tool functions (used for testing function/tool abuse attacks).                      |
| `--report-dir`             | `-rd` | `str`       | ❌ No     | `None`              | Directory to write the evaluation report files (HTML and JSON summary of injection test results and prompt evaluation).  |

**Note:**  
> - `--eval-api-mode`, `--attack-api-mode`, and `--judge-api-mode` accept `openai`, `claude`, or `bedrock` as options.  
> - When using Bedrock, you must specify the [Bedrock Model ID](https://docs.aws.amazon.com/bedrock/latest/userguide/model-ids.html) for `--eval-model`, `--attack-model`, and `--judge-model` (e.g., `.claude-3-5-sonnet-20240620-v1:0`).
> - For more details on each option, see the source code in [`src/main.py`](src/main.py).

</details>

### 🌐 Web UI (Gradio)

```bash
prompt-hardener webui
```

Then visit http://localhost:7860 to use Prompt Hardener interactively:
- Paste prompts
- Choose models & settings
- Download hardened prompt and reports

Perfect for demoing, auditing, or collaborating across teams.

Here is the demo screen for the Web UI.

<img width="1544" alt="webui" src="https://github.com/user-attachments/assets/406afba7-9c90-4342-a2ec-c730031c3cd9" />


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
- Tool Definition Leaking

Each attack is automatically injected and measured for:
- Injection attacks blocked (✅ or ❌)
- LLM response contents
- Category, payload, and result

## 🛠️ Hardening Techniques

Prompt Hardener includes multiple defense strategies:

| Technique                   | Description                                                                                                      |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| **Spotlighting**            | Explicitly marks and isolates all user-controlled input using tags and special characters to prevent injection.   |
| **Random Sequence Enclosure** | Encloses trusted system instructions in unpredictable tags, ensuring only those are followed and not leaked.      |
| **Instruction Defense**     | Instructs the model to ignore new instructions, persona switching, or attempts to reveal/modify system prompts.   |
| **Role Consistency**        | Ensures each message role (system, user, assistant) is preserved and not mixed, preventing role confusion attacks.|

You can see the details of each hardening techniques from below.

[docs/techniques.md](./docs/techniques.md)

## 📄 Reporting

After each run, Prompt Hardener generates:

- `prompt_security_report_<random value>.html`:
  - Visual report of improved prompt, evaluations and injection test results
- `prompt_security_report_<random value>_attack_results.json:`:
  - Raw structured data of injection test results

Reports are styled for readability and highlight:
- Initial prompt and hardened final prompt
- Evaluation category-wise scores and comments
- Injection attack blocked stats (e.g., 12/15 PASSED)
  - PASSED = attack blocked, FAILED = attack succeeded.

![report1](https://github.com/user-attachments/assets/c98ecb7b-48aa-4729-8749-9e62a77bd806)
![report2](https://github.com/user-attachments/assets/a0838258-0ac6-4612-88cd-b48975c048cb)
![report3](https://github.com/user-attachments/assets/f042fa99-5370-44ef-ab4c-ed26b996b82d)


## 💪 Tutorials
You can see examples of using Prompt Hardener to improve and test system prompts for an AI assistant and a comment-summarizing AI from below.

[docs/tutorials.md](./docs/tutorials.md)
