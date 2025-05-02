import argparse
from evaluate import evaluate_prompt
from improve import improve_prompt


# Argument parser setup
def parse_args():
    parser = argparse.ArgumentParser(
        description="Evaluate and improve the security of a prompt using OpenAI or Ollama API with self-refinement."
    )
    parser.add_argument(
        "-t",
        "--target-prompt-path",
        type=str,
        required=True,
        help="Path to the file containing the target prompt.",
    )
    parser.add_argument(
        "-am",
        "--api-mode",
        type=str,
        choices=["openai", "ollama"],
        required=True,
        help="Select the API mode: 'openai' or 'ollama'.",
    )
    parser.add_argument(
        "-m",
        "--model",
        type=str,
        required=True,
        help="Specify the model name (e.g., 'gpt-3.5-turbo', 'gpt-4', or 'llama3.1').",
    )
    parser.add_argument(
        "-ui",
        "--user-input-description",
        type=str,
        required=False,
        help="Description or clarification for user inputs in the target prompt.",
    )
    parser.add_argument(
        "-o",
        "--output-path",
        type=str,
        required=True,
        help="Path to the file where the improved prompt will be written.",
    )
    parser.add_argument(
        "-n",
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum number of self-refinement iterations.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.85,
        help="Evaluation score threshold to consider the prompt sufficiently secure.",
    )
    parser.add_argument(
        "--apply-techniques",
        nargs="+",
        choices=[
            "spotlighting",
            "signed_prompt",
            "rule_reinforcement",
            "structured_output",
        ],
        help="Specify which techniques to apply during improvement. Defaults to all.",
    )
    return parser.parse_args()


# Load the target prompt from file
def load_target_prompt(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: The file at path '{file_path}' was not found.")
        exit(1)
    except IOError as e:
        print(
            f"Error: An I/O error occurred while reading the file '{file_path}'.\nDetails: {e}"
        )
        exit(1)


# Write the final improved prompt to file
def write_to_file(output_path, content):
    try:
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(content)
        print(f"Improved prompt written to: {output_path}")
    except IOError as e:
        print(
            f"Error: An I/O error occurred while writing to the file '{output_path}'.\nDetails: {e}"
        )
        exit(1)


# Calculate average satisfaction score across all subfields
def average_satisfaction(evaluation):
    if not isinstance(evaluation, dict):
        return 0.0
    total = 0
    count = 0
    for category, items in evaluation.items():
        if category in ("critique", "recommendation"):
            continue
        for subkey, subval in items.items():
            if isinstance(subval, dict) and "satisfaction" in subval:
                try:
                    total += float(subval["satisfaction"])
                    count += 1
                except (ValueError, TypeError):
                    continue
    return (total / count / 10.0) if count > 0 else 0.0


# Main execution
def main():
    args = parse_args()
    current_prompt = load_target_prompt(args.target_prompt_path)

    for i in range(args.max_iterations):
        print(f"\n--- Iteration {i + 1} ---")
        evaluation_result = evaluate_prompt(
            args.api_mode, args.model, current_prompt, args.user_input_description
        )
        print("Evaluation Result:")
        print(evaluation_result)

        avg_score = average_satisfaction(evaluation_result)
        print(f"Average Satisfaction Score: {avg_score:.2f}")

        if avg_score >= args.threshold:
            print("Prompt meets the required security threshold. Stopping refinement.")
            break

        current_prompt = improve_prompt(
            args.api_mode,
            args.model,
            current_prompt,
            evaluation_result,
            args.user_input_description,
            apply_techniques=args.apply_techniques,
        )
        print("Improved Prompt:")
        print(current_prompt)

    write_to_file(args.output_path, current_prompt)


if __name__ == "__main__":
    main()
