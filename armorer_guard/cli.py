from __future__ import annotations

import argparse
import json
import sys

from . import detect_credentials, inspect_input, sanitize_text


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Armorer Guard from Python package")
    parser.add_argument("mode", nargs="?", choices=["inspect", "sanitize", "detect-credentials"], default="inspect")
    args = parser.parse_args()
    text = sys.stdin.read()
    if args.mode == "sanitize":
        print(sanitize_text(text))
        return 0
    if args.mode == "detect-credentials":
        result = detect_credentials(text)
        print(json.dumps(None if result is None else result.__dict__))
        return 0
    print(json.dumps(inspect_input(text).__dict__))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
