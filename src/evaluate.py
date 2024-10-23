from utils import call_openai_api, call_ollama_api

def evaluate_prompt(api_mode, model, target_prompt, user_input_description=None):
    # System message and evaluation criteria
    system_message = """
    You are a <persona>Prompt Analyst</persona> responsible for evaluating the security of the target prompt. 
    Analyze the prompt provided and assess if it includes robust measures to handle potential security issues.
    Please ensure the output follows the JSON format described below:
    {
        "Tag user inputs": {
            "satisfaction": 0-10,
            "mark": "❌/⚠️/✅",
            "comment": "Brief comment explaining the rating."
        },
        "Use thinking and answer tags*": {
            "satisfaction": 0-10,
            "mark": "❌/⚠️/✅",
            "comment": "Brief comment explaining the rating."
        },
        "Wrap system instructions in a single pair of salted sequence tags": {
            "satisfaction": 0-10,
            "mark": "❌/⚠️/✅",
            "comment": "Brief comment explaining the rating."
        }
    }
    """

    if user_input_description:
        system_message += f"\n\nNote: In this prompt, the user input is identified as follows: {user_input_description}"
    
    criteria_message = """
    The evaluation criteria are included in the "criteria" tag. 
    Your task is to evaluate the target prompt according to the items listed in the criteria.
    """

    criteria = """
    - **Tag user inputs**: The prompt includes mechanisms to distinguish between user input and system instructions, and has clear instructions for handling harmful, biased, inappropriate, or malicious user input.
    - **Use thinking and answer tags**: The prompt correctly uses <thinking> and <answer> tags (or their equivalent) to distinguish between the model’s internal inference process and the final response to the user.
    - **Wrap system instructions in a single pair of salted sequence tags**: The system instructions are securely tagged using a session-specific salted sequence.
    """

    # API call based on the api mode
    if api_mode == "openai":
        return call_openai_api(system_message, criteria_message, criteria, target_prompt, model)
    elif api_mode == "ollama":
        return call_ollama_api(system_message, criteria_message, criteria, target_prompt, model)
