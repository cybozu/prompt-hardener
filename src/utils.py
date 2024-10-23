import requests
from openai import OpenAI

# Initialize the OpenAI client
client = OpenAI()

# Function to call the OpenAI API
def call_openai_api(system_message, criteria_message, criteria, target_prompt, model_name):
    try:
        completion = client.chat.completions.create(
            model=model_name,  
            messages=[
                {"role": "system", "content": system_message},
                {
                    "role": "system",
                    "content": f"The evaluation criteria are:\n{criteria_message}\n{criteria}",
                },
                {"role": "user", "content": f"The target prompt is:\n{target_prompt}"},
            ],
            max_tokens=1500,
            temperature=0.2,
        )
        return completion.choices[0].message.content
    except Exception as e:
        raise ValueError(f"Error: An error occurred while calling the OpenAI API with model '{model_name}': {e}")

# Function to call the Ollama API
def call_ollama_api(system_message, criteria_message, criteria, target_prompt, model_name):
    OLLAMA_API_URL = "http://localhost:11434/api/chat"  # Default Ollama local API URL
    try:
        response = requests.post(
            OLLAMA_API_URL,
            json={
                "model": model_name,  
                "messages": [
                    {"role": "system", "content": system_message},
                    {
                        "role": "system",
                        "content": f"The evaluation criteria are:\n{criteria_message}\n{criteria}",
                    },
                    {"role": "user", "content": f"The target prompt is:\n{target_prompt}"},
                ],
                "stream": False,
            },
        )
        res = response.json()
        result = res.get("message", {})
        content = result.get("content", "")
        return content
    except Exception as e:
        raise ValueError(f"Error: An error occurred while calling the Ollama API with model '{model_name}': {e}")