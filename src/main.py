import argparse
from evaluate import evaluate_prompt
from improve import improve_prompt
from attack import run_injection_test


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
        help="Specify the model name (e.g., 'gpt-4').",
    )
    parser.add_argument(
        "-ui",
        "--user-input-description",
        type=str,
        required=False,
        help="Clarification for user inputs in the prompt.",
    )
    parser.add_argument(
        "-o",
        "--output-path",
        type=str,
        required=True,
        help="Path to write the improved prompt.",
    )
    parser.add_argument(
        "-n",
        "--max-iterations",
        type=int,
        default=3,
        help="Max number of self-refinement iterations.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.85,
        help="Average satisfaction threshold to stop refinement.",
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
        help="Techniques to apply during improvement.",
    )
    parser.add_argument(
        "--test-after",
        action="store_true",
        help="Whether to test improved prompt against known injection patterns.",
    )
    parser.add_argument(
        "--test-model",
        type=str,
        default="gpt-3.5-turbo",
        help="Model to use for post-improvement injection test.",
    )
    return parser.parse_args()


# Load the target prompt from file
def load_target_prompt(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return file.read()


# Write the final improved prompt to file
def write_to_file(output_path, content):
    with open(output_path, "w", encoding="utf-8") as file:
        file.write(content)
    print(f"Improved prompt written to: {output_path}")


# Calculate average satisfaction score
def average_satisfaction(evaluation):
    total, count = 0, 0
    for category, items in evaluation.items():
        if category in ("critique", "recommendation"):
            continue
        for sub in items.values():
            try:
                total += float(sub["satisfaction"])
                count += 1
            except:
                continue
    return (total / count / 10.0) if count else 0.0


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

    if args.test_after:
        test_model = args.test_model or args.model
        print("\n--- Running injection test on final prompt ---")
        run_injection_test(
            current_prompt, test_model, apply_techniques=args.apply_techniques
        )


if __name__ == "__main__":
    main()
