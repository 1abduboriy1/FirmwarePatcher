# FirmwarePatcher

A local, AI-powered firmware analysis tool designed to inspect binary blobs, detect magic numbers, and hunt for hidden credentials. It provides a readable hex dump and uses a local LLM to analyze extracted strings for security vulnerabilities.

## Features
* **Hex Dump Visualization:** Generates a clean, annotated 16-byte row hex dump using `rich`.
* **Pattern Detection:** Scans for known magic numbers (ELF, ZIP, U-Boot) and uses regex to find planted credentials and secrets.
* **LLM Commentary:** Pipes extracted ASCII strings to a local LLM (`ollama`) for expert security analysis.

## Tech Stack
* Python 3
* `ollama` (Local LLM runner)
* `rich` (Terminal formatting)
* `binascii`, `struct`, `re` (Standard libraries)

## Setup & Usage

Follow these steps in order to set up your environment, generate the test binary, and run the analysis.

### 1. Install Dependencies
Install the required Python packages:
```bash
pip install rich ollama