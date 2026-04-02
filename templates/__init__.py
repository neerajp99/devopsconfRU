"""
Prompt templates for AI agents
Ensures consistent, structured prompts with constraints
"""
from pathlib import Path

TEMPLATES_DIR = Path(__file__).parent


def load_template(template_name: str) -> str:
    """Load prompt template from file"""
    template_path = TEMPLATES_DIR / f"{template_name}_prompt.txt"
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_name}")

    with open(template_path, "r") as f:
        return f.read()


def get_detective_prompt() -> str:
    """Get Detective Agent prompt template"""
    return load_template("detective")


def get_surgeon_prompt() -> str:
    """Get Surgeon Agent prompt template"""
    return load_template("surgeon")


def get_checker_prompt() -> str:
    """Get Checker Agent prompt template"""
    return load_template("checker")
