from rich.console import Console
from rich.text import Text

console = Console()

STYLES = {
    "[*]": "bold bright_blue",
    "[+]": "bold bright_green",
    "[-]": "bold bright_red",
    "[!]": "bold bright_yellow"
}

def print_colour(message: str):
    prefix = next((p for p in STYLES if message.startswith(p)), "")
    style = STYLES.get(prefix, "default")
    symbol = Text(prefix + " ", style=style) if prefix else Text("")

    content = message[len(prefix):].strip()
    styled = [
        Text(word, style="bold bright_cyan" if '.' in word and any(c.isdigit() for c in word) else "default")
        for word in content.split()
    ]

    console.print(symbol + Text(" ").join(styled))
