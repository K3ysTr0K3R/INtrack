from rich.console import Console
from rich.text import Text

console = Console()

def print_green(message):
    symbol = Text("[+] ", style="bold bright_green")
    text = Text(message, style="default")
    console.print(symbol + text)

def print_blue(message):
    symbol = Text("[*] ", style="bold bright_blue")
    text = Text(message, style="default")
    console.print(symbol + text)

def print_red(message):
    symbol = Text("[-] ", style="red")
    text = Text(message, style="default")
    console.print(symbol + text)

def print_yellow(message):
    symbol = Text("[!] ", style="yellow")
    text = Text(message, style="default")
    console.print(symbol + text)
