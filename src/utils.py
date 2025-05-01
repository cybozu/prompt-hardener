import json
from openai import OpenAI

client = OpenAI()


def build_openai_messages(system_message, criteria_message, criteria, target_prompt, json_response=True):
    user_instruction = (
        f"The target prompt is:\n{target_prompt}\n\n"
        f"Please evaluate or improve the above according to the criteria and respond in JSON."
        if json_response
        else f"The target prompt is:\n{target_prompt}"
    )
    return [
        {"role": "system", "content": system_message},
        {"role": "system", "content": f"The evaluation criteria are:\n{criteria_message}\n{criteria}"},
        {"role": "user", "content": user_instruction},
    ]


def call_openai_api(
    system_message: str,
    criteria_message: str,
    criteria: str,
    target_prompt: str,
    model_name: str,
    json_response: bool = True,
):
    try:
        messages = build_openai_messages(
            system_message, criteria_message, criteria, target_prompt, json_response
        )
        response_format = {"type": "json_object"} if json_response else None

        completion = client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=0.2,
            max_tokens=1500,
            response_format=response_format,
        )
        content = completion.choices[0].message.content
        return json.loads(content) if json_response else content

    except Exception as e:
        raise ValueError(
            f"Error: An error occurred while calling the OpenAI API with model '{model_name}': {e}"
        )
