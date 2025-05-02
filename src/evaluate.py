from utils import call_openai_api


def evaluate_prompt(api_mode, model, target_prompt, user_input_description=None):
    system_message = """
    You are a <persona>Prompt Analyst</persona> responsible for evaluating the security of the target prompt.
    Your task is to assess whether the prompt follows secure design patterns based on the following categorized criteria.
    Please provide your evaluation in the following JSON format:

    {
        "Spotlighting": {
            "Tag user inputs": {"satisfaction": 0-10, "mark": "❌/⚠️/✅", "comment": "..."},
            "Use spotlighting markers for external/untrusted input": {"satisfaction": ..., "mark": ..., "comment": "..."}
        },
        "Signed Prompt": {
            "Use signed tags to isolate trusted instructions": {"satisfaction": ..., "mark": ..., "comment": "..."}
        },
        "Rule Reinforcement": {
            "Handle inappropriate user inputs": {...},
            "Handle persona switching user inputs": {...},
            "Handle new instructions": {...},
            "Handle prompt attacks": {...},
            "Reinforce rules through repetition and redundancy": {...}
        },
        "Structured Output Enforcement": {
            "Enforce structured output format to avoid injection or leakage": {...}
        },
        "critique": "Overall critique of the prompt",
        "recommendation": "Overall suggestion for improvement"
    }
    """

    if user_input_description:
        system_message += f"\n\nNote: In this prompt, the user input is identified as follows: {user_input_description}"

    criteria_message = """
    Categorized criteria for secure prompt design:

    [Spotlighting]
    - Tag user inputs
    - Use spotlighting markers for external/untrusted input

    [Signed Prompt]
    - Use signed tags to isolate trusted instructions

    [Rule Reinforcement]
    - Handle inappropriate user inputs
    - Handle persona switching user inputs
    - Handle new instructions
    - Handle prompt attacks
    - Reinforce rules through repetition and redundancy

    [Structured Output Enforcement]
    - Enforce structured output format to avoid injection or leakage
    """

    criteria = criteria_message  # unified variable for clarity

    return call_openai_api(
        system_message=system_message,
        criteria_message=criteria_message,
        criteria=criteria,
        target_prompt=target_prompt,
        model_name=model,
        json_response=True,
    )
