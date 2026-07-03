#!/usr/bin/env python3
"""
AFEM CLI — Run Agent
====================
Run the AFEM email agent from the command line.

Usage
-----
    python scripts/run_agent.py "Find all emails related to payroll"
    python scripts/run_agent.py --prompt "Show me emails from hr@enron.com"
    python scripts/run_agent.py --interactive
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Ensure AFEM root is on sys.path so all AFEM imports resolve correctly.
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import config  # noqa: F401
from agent.langgraph_agent import run_agent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    stream=sys.stdout,
)

logger = logging.getLogger("afem.cli")


def _run_once(prompt: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  Prompt: {prompt}")
    print(f"{'─' * 60}\n")

    response = run_agent(prompt)

    print("\n── Agent Response ─────────────────────────────────────────")
    print(response)
    print("───────────────────────────────────────────────────────────")


def _interactive() -> None:
    print("AFEM Interactive Agent (type 'quit' to exit)\n")

    while True:
        try:
            prompt = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not prompt:
            continue

        if prompt.lower() in {"quit", "exit", "q"}:
            break

        _run_once(prompt)


def main() -> None:
    parser = argparse.ArgumentParser(description="AFEM Email Agent CLI")

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "prompt",
        nargs="?",
        help="Prompt string (positional)",
    )

    group.add_argument(
        "--prompt",
        dest="prompt_flag",
        help="Prompt string (flag form)",
    )

    group.add_argument(
        "--interactive",
        action="store_true",
        help="Interactive REPL mode",
    )

    args = parser.parse_args()

    prompt = args.prompt or args.prompt_flag

    if args.interactive:
        _interactive()
    elif prompt:
        _run_once(prompt)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()