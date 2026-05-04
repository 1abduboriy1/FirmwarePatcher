import struct
import binascii
import re
from pathlib import Path
import ollama
from rich.console import Console
from rich.table import Table

console = Console()

def generate_hexdump(data: bytes, limit: int = 256) -> Table:
    """Generates a formatted hex dump table using rich."""
    table = Table(title="Firmware Hex Dump", show_header=True, header_style="bold magenta")
    table.add_column("Offset", style="cyan", justify="right")
    table.add_column("Hex", style="green")
    table.add_column("ASCII", style="yellow")

    # Limit the display so we don't flood the terminal on massive binaries
    display_data = data[:limit]

    for i in range(0, len(display_data), 16):
        chunk = display_data[i:i+16]
        offset = f"{i:08x}"
        
        # Format hex: '00 11 22 33'
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex string if it's the last row and less than 16 bytes
        hex_str = hex_str.ljust(47) 
        
        # Format ASCII: replace non-printable chars with '.'
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        
        table.add_row(offset, hex_str, ascii_str)

    return table

def custom_pattern_detector(data: bytes):
    """
    Scans the raw bytes for standard magic numbers and a custom 
    regex tailored to find planted credentials.
    """
    findings = []
    
    # 1. Magic Number Detection
    if data.startswith(b'\x7fELF'):
        findings.append(("[Magic Number]", "ELF Executable detected at offset 0x00000000"))
    elif data.startswith(b'PK\x03\x04'):
        findings.append(("[Magic Number]", "ZIP Archive detected at offset 0x00000000"))
    elif b'U-Boot' in data:
        findings.append(("[Bootloader]", "U-Boot string detected in binary"))

    # 2. NEW PATTERN DETECTOR: Hidden Credentials
    # Looks for common keys like password, admin, root, key, token followed by strings
    cred_pattern = re.compile(b'(?i)(password|passwd|pwd|key|token|admin|root|secret)[\s:=]*([a-zA-Z0-9_\-\.\!\@\#\$\%\^\&\*]{5,})')
    
    for match in cred_pattern.finditer(data):
        offset = match.start()
        decoded_match = match.group(0).decode('ascii', errors='ignore')
        findings.append(("[Credential Pattern]", f"Suspicious string '{decoded_match}' found at offset {offset:#08x}"))

    return findings

def get_llm_commentary(data: bytes) -> str:
    """Extracts strings and asks the local LLM to analyze them."""
    # Convert to an ASCII representation to feed the LLM, dropping binary garbage
    ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in data)
    
    # Clean it up by finding continuous blocks of text to save context window space
    printable_strings = re.findall(r'[ -~]{4,}', ascii_text)
    clean_context = "\n".join(printable_strings)

    prompt = f"""
    You are an expert hardware security researcher. Analyze the following extracted ASCII strings from a firmware binary dump. 
    Identify any suspicious strings, hardcoded credentials, debug paths, or recognizable structures.
    Keep your commentary brief, punchy, and focused on security vulnerabilities.

    Extracted Strings:
    {clean_context[:2000]}  # Limiting context to avoid token overflow
    """

    try:
        # Assuming you have the 'llama3' model pulled locally. Change if needed.
        response = ollama.chat(model='llama3', messages=[
            {'role': 'user', 'content': prompt}
        ])
        return response['message']['content']
    except Exception as e:
        return f"[red]Failed to connect to Ollama: {e}[/red]\nMake sure Ollama is running (`ollama serve`)."

def main():
    # 1. Load the simulated firmware binary
    filepath = Path("assets/firmware_blob.bin")
    if not filepath.exists():
        console.print(f"[bold red]Error:[/bold red] Could not find {filepath}. Make sure you are running this from the right directory.")
        return

    console.print("[bold blue][*] Loading firmware binary...[/bold blue]")
    data = filepath.read_bytes()
    file_size = len(data)
    console.print(f"Loaded {file_size} bytes.\n")

    # 2. Display formatted hex dump (First 256 bytes to keep terminal clean)
    hex_table = generate_hexdump(data, limit=256)
    console.print(hex_table)
    if file_size > 256:
        console.print("[cyan]... (Hex dump truncated for display) ...[/cyan]\n")

    # 3. Add and execute the new pattern detector
    console.print("[bold blue][*] Running deterministic pattern matching...[/bold blue]")
    findings = custom_pattern_detector(data)
    
    if findings:
        for tag, description in findings:
            console.print(f"[bold yellow]{tag}[/bold yellow] {description}")
    else:
        console.print("[green]No obvious magic numbers or credentials found via regex.[/green]")
    
    console.print()

    # 4. LLM Commentary
    console.print("[bold blue][*] Passing extracted strings to local LLM for analysis...[/bold blue]")
    with console.status("[bold green]Ollama is thinking...[/bold green]", spinner="dots"):
        llm_commentary = get_llm_commentary(data)
        
    console.print("\n[bold magenta]--- LLM Security Commentary ---[/bold magenta]")
    console.print(llm_commentary)

if __name__ == "__main__":
    main()