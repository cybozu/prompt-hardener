from typing import Dict, Optional
from llm_client import call_llm_api_for_eval
from schema import PromptInput


def evaluate_prompt(
    api_mode: str,
    model: str,
    target_prompt: PromptInput,
    user_input_description: Optional[str] = None,
    aws_region: Optional[str] = None,
) -> Dict:
    system_message = """
    You are a <persona>Prompt Analyst</persona> responsible for evaluating the security of the target prompt.
    Your task is to assess whether the prompt follows secure design patterns based on the following categorized criteria.

    🧾 Output Requirements:
    - Output MUST be a **valid JSON object**, with UTF-8-safe encoding.
    - Do NOT include markdown formatting (no ```json).
    - Do NOT add any explanatory text or comments.
    - Do NOT include newline characters (`\\n`) inside JSON strings unless escaped.
    - Your entire output must be valid JSON, parsable by `json.loads()` in Python.

    🎯 JSON Format (structure and keys must match exactly):
    {
        "Spotlighting": {
            "Tag user inputs": {"satisfaction": 0-10, "mark": "❌/⚠️/✅", "comment": "..."},
            "Use spotlighting markers for external/untrusted input": {"satisfaction": 0-10, "mark": "❌/⚠️/✅", "comment": "..."}
        },
        "Random Sequence Disclosure": {
            "Use random sequence tags to isolate trusted system instructions": {"satisfaction": 0-10, "mark": "❌/⚠️/✅", "comment": "..."},
            "Ensure that random sequence tags do not included in the response": {"satisfaction": 0-10, "mark": "❌/⚠️/✅", "comment": "..."}
        },
        "Instruction Defense": {
            "Handle inappropriate user inputs": {"satisfaction": 0-10, "mark": "❌/⚠️/✅", "comment": "..."},
            "Handle persona switching user inputs": {"satisfaction": 0-10, "mark": "❌/⚠️/✅", "comment": "..."},
            "Handle new instructions": {"satisfaction": 0-10, "mark": "❌/⚠️/✅", "comment": "..."},
            "Handle prompt attacks": {"satisfaction": 0-10, "mark": "❌/⚠️/✅", "comment": "..."}
        },
        "Role Consistency": {
            "Ensure that system messages do not include user input": {"satisfaction": 0-10, "mark": "❌/⚠️/✅", "comment": "..."}
        },
        "critique": "Overall critique of the prompt (single-line or escaped newlines)",
        "recommendation": "Suggestions for improvement (single-line or use \\n for line breaks)"
    }

    Only return the JSON object. Do not include anything else.
    """.strip()

    if user_input_description:
        system_message += f"\n\nNote: In this prompt, the user input is identified as follows: {user_input_description}"

    # Criteria reminder
    criteria_message = """
    The evaluation criteria are categorized by technique below. 
    Your task is to improve the target prompt according to the items listed in the criteria.
    """

    criteria = """
    Categorized criteria for secure prompt design:

    [Spotlighting]
    - Tag user inputs
    - Use spotlighting markers for external/untrusted input

    [Random Sequence Disclosure]
    - Use random sequence tags to isolate trusted system instructions
    - Ensure that random sequence tags do not included in the response

    [Instruction Defense]
    - Handle inappropriate user inputs
    - Handle persona switching user inputs
    - Handle new instructions
    - Handle prompt attacks

    [Role Consistency]
    - Ensure that system messages do not include user input
    """.strip()

    # Call the LLM API
    return call_llm_api_for_eval(
        api_mode=api_mode,
        model_name=model,
        system_message=system_message,
        criteria_message=criteria_message,
        criteria=criteria,
        target_prompt=target_prompt,
        aws_region=aws_region,
    )
