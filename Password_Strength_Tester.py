import math
import re
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Character sets
LOWERCASE = r"[a-z]"
UPPERCASE = r"[A-Z]"
DIGITS = r"[0-9]"
SYMBOLS = r"[^a-zA-Z0-9]"

# Common passwords (can be expanded)
COMMON_PASSWORDS = {
    "password", "123456", "qwerty", "abc123", "111111", "letmein", "admin", "welcome"
}

def calculate_entropy(password):
    """Calculate password entropy based on character diversity and length."""
    if not password:
        return 0.0

    charset_size = 0
    if re.search(LOWERCASE, password):
        charset_size += 26
    if re.search(UPPERCASE, password):
        charset_size += 26
    if re.search(DIGITS, password):
        charset_size += 10
    if re.search(SYMBOLS, password):
        charset_size += 33  # Common printable symbols

    # Avoid log(0) error
    if charset_size == 0:
        return 0.0

    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)

def assess_strength(password):
    """Assess password strength with improved logic."""
    password = password.strip()

    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        return "Very Weak", 0.0, ["Password is too common. Avoid easy guesses."]

    # Empty password check
    if not password:
        return "Very Weak", 0.0, ["Password cannot be empty."]

    entropy = calculate_entropy(password)
    suggestions = []

    # Add suggestions dynamically
    if not re.search(LOWERCASE, password):
        suggestions.append("Add lowercase letters.")
    if not re.search(UPPERCASE, password):
        suggestions.append("Add uppercase letters.")
    if not re.search(DIGITS, password):
        suggestions.append("Include numbers.")
    if not re.search(SYMBOLS, password):
        suggestions.append("Add symbols for complexity.")
    if len(password) < 8:
        suggestions.append("Increase length to at least 12 characters for better security.")

    # Strength classification
    if entropy < 28:
        strength = "Very Weak"
    elif entropy < 36:
        strength = "Weak"
    elif entropy < 60:
        strength = "Moderate"
    elif entropy < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return strength, entropy, suggestions

def main():
    print(Fore.CYAN + "=== ADVANCED PASSWORD STRENGTH ANALYZER ===\n")
    while True:
        password = input("Enter a password (or type 'exit' to quit): ").strip()
        if password.lower() == "exit":
            print(Fore.YELLOW + "\nGoodbye! 👋 Stay safe online.")
            break

        strength, entropy, suggestions = assess_strength(password)

        # Display results
        print(f"\n🔒 Strength: {Fore.GREEN if strength in ['Strong', 'Very Strong'] else Fore.RED}{strength}{Style.RESET_ALL}")
        print(f"🔢 Entropy: {entropy} bits")

        if suggestions:
            print(f"{Fore.YELLOW}Notes/Suggestions:{Style.RESET_ALL}")
            for s in suggestions:
                print(f"- {s}")
        print()  # Blank line for readability

if __name__ == "__main__":
    main()