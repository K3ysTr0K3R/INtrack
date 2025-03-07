from rich.console import Console
from rich.text import Text

console = Console()

def print_colour(message):
	if message.startswith("[*]"):
		symbol = Text("[*] ", style="bold bright_blue")
	elif message.startswith("[+]"):
		symbol = Text("[+] ", style="bold bright_green")
	elif message.startswith("[-]"):
		symbol = Text("[-] ", style="bold bright_red")
	elif message.startswith("[!]"):
		symbol = Text("[!] ", style="bold bright_yellow")
	else:
		symbol = Text("", style="default")

	text_without_symbol = message[len(symbol.plain):].strip()

	words = text_without_symbol.split()
	styled_parts = []

	for word in words:
		if '.' in word and any(char.isdigit() for char in word):
			styled_parts.append(Text(word, style="bold bright_cyan"))
		else:
			styled_parts.append(Text(word, style="default"))

	combined_text = symbol + Text(" ").join(styled_parts)
	console.print(combined_text)
