import argparse
from evaluate import evaluate_prompt
from improve import improve_prompt

# Argument parser setup
def parse_args():
    parser = argparse.ArgumentParser(
        description="Evaluate and improve the security of a prompt using OpenAI or Ollama API."
    )
    parser.add_argument(
        "-t", "--target-prompt-path", type=str, required=True,
        help="Path to the file containing the target prompt."
    )
    parser.add_argument(
        "-am", "--api-mode", type=str, choices=["openai", "ollama"], required=True,
        help="Select the API mode: 'openai' or 'ollama'."
    )
    parser.add_argument(
        "-m", "--model", type=str, required=True,
        help="Specify the model name (e.g., 'gpt-3.5-turbo' or 'gpt-4' for OpenAI; 'llama3.1' for Ollama)."
    )
    parser.add_argument(
        "-ui", "--user-input-description", type=str, required=False,
        help="Provide a description or clarification for user inputs in the target prompt."
    )
    parser.add_argument(
        "-o", "--output-path", type=str, required=True,
        help="Path to the file where the improved prompt will be written."
    )
    return parser.parse_args()

# Function to load the target prompt
def load_target_prompt(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: The file at path '{file_path}' was not found.")
        exit(1)
    except IOError as e:
        print(f"Error: An I/O error occurred while reading the file '{file_path}'.\nDetails: {e}")
        exit(1)

# Function to write the improved prompt to a file
def write_to_file(output_path, content):
    try:
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(content)
        print(f"Improved prompt written to: {output_path}")
    except IOError as e:
        print(f"Error: An I/O error occurred while writing to the file '{output_path}'.\nDetails: {e}")
        exit(1)

# Main function
def main():
    args = parse_args()

    # Load the target prompt from the file
    target_prompt = load_target_prompt(args.target_prompt_path)

    # Step 1: Evaluate the prompt
    print("Evaluating the prompt...")
    evaluation_result = evaluate_prompt(args.api_mode, args.model, target_prompt, args.user_input_description)
    print("Evaluation Result:")
    print(evaluation_result)

    # Step 2: Use the evaluation result to improve the prompt
    print("\nImproving the prompt based on the evaluation...")
    improved_prompt = improve_prompt(args.api_mode, args.model, target_prompt, evaluation_result, args.user_input_description)
    print("Improvement Suggestions:")
    print(improved_prompt)

    # Write the improved prompt to the specified file
    write_to_file(args.output_path, improved_prompt)

if __name__ == "__main__":
    main()
