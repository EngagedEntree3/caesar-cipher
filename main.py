#!/usr/bin/env python3
"""Caesar cipher — command line interface.

    ./main.py encrypt "Attack at dawn!" --shift 3
    ./main.py decrypt "Dwwdfn dw gdzq!" --shift 3
    ./main.py crack   "Dwwdfn dw gdzq!" --rank

Text can also arrive on stdin, which is how you handle files and pipelines:

    cat secret.txt | ./main.py encrypt --shift 13 > secret.enc
    ./main.py crack < secret.enc | head -5

All cipher logic lives in ``caesar/cipher.py``. This file only parses
arguments, moves text in and out, and formats results — keeping the two apart
is what lets the core be imported and tested without touching argv or stdout.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Sequence

# Allow running the script directly from a checkout without installing it.
# os.path rather than string splitting on "/", so this also works on Windows
# and when invoked through a symlink or a relative path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from caesar.cipher import Candidate, brute_force, decrypt, encrypt  # noqa: E402

EXIT_OK = 0
EXIT_USAGE = 2


def read_text(argument: Optional[str], stream=None) -> str:
    """Resolve the input text from the argument, falling back to stdin.

    Only a single trailing newline is stripped — the one a shell or editor
    adds. Other whitespace is left alone, because leading spaces and internal
    blank lines are legitimate parts of a message.
    """
    if argument is not None:
        return argument

    stream = stream if stream is not None else sys.stdin
    data = stream.read()
    return data[:-1] if data.endswith("\n") else data


def format_candidates(candidates: Sequence[Candidate], show_score: bool) -> List[str]:
    """Render brute-force results as aligned, pipe-friendly lines."""
    lines = []
    for candidate in candidates:
        if show_score:
            lines.append(f"{candidate.shift:>2}  {candidate.score:8.1f}  {candidate.text}")
        else:
            lines.append(f"{candidate.shift:>2}  {candidate.text}")
    return lines


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser.

    Exposed separately so tests can inspect it without running a command.
    """
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Encrypt, decrypt and crack Caesar ciphers.",
        epilog=(
            "Text may be given as an argument or piped on stdin. "
            "The Caesar cipher is educational only and provides no real security."
        ),
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s 1.0.0"
    )

    subcommands = parser.add_subparsers(dest="command", metavar="COMMAND")
    subcommands.required = True

    def add_text_argument(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument(
            "text",
            nargs="?",
            default=None,
            help="text to process (omit to read from stdin)",
        )

    encrypt_parser = subcommands.add_parser(
        "encrypt", help="encrypt plaintext with a shift key"
    )
    add_text_argument(encrypt_parser)
    encrypt_parser.add_argument(
        "-s",
        "--shift",
        type=int,
        required=True,
        metavar="N",
        help="shift key; any integer, including negative or above 26",
    )

    decrypt_parser = subcommands.add_parser(
        "decrypt", help="decrypt ciphertext with a known shift key"
    )
    add_text_argument(decrypt_parser)
    decrypt_parser.add_argument(
        "-s",
        "--shift",
        type=int,
        required=True,
        metavar="N",
        help="shift key the text was encrypted with",
    )

    crack_parser = subcommands.add_parser(
        "crack", help="try all 25 shifts when the key is unknown"
    )
    add_text_argument(crack_parser)
    crack_parser.add_argument(
        "-r",
        "--rank",
        action="store_true",
        help="sort by how English-like each result looks, best first",
    )
    crack_parser.add_argument(
        "-t",
        "--top",
        type=int,
        default=None,
        metavar="N",
        help="show only the first N results",
    )

    return parser


def main(argv: Optional[List[str]] = None, stdin=None, stdout=None) -> int:
    """Run the CLI. Returns the process exit status.

    ``stdin``/``stdout`` are injectable so the tests can drive the whole
    command without touching the real process streams.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    out = stdout if stdout is not None else sys.stdout

    text = read_text(args.text, stdin)

    if args.command == "encrypt":
        print(encrypt(text, args.shift), file=out)
    elif args.command == "decrypt":
        print(decrypt(text, args.shift), file=out)
    elif args.command == "crack":
        if args.top is not None and args.top < 1:
            parser.error("--top must be 1 or greater")
        candidates = brute_force(text)
        if args.rank:
            candidates = sorted(candidates, key=lambda c: c.score)
        if args.top is not None:
            candidates = candidates[: args.top]
        for line in format_candidates(candidates, show_score=args.rank):
            print(line, file=out)
    else:  # pragma: no cover - argparse rejects unknown commands first
        parser.error(f"unknown command: {args.command}")

    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        # Expected when the reader goes away, e.g. `./main.py crack | head -3`.
        # Close stdout explicitly so Python does not print a second error
        # about it during interpreter shutdown.
        try:
            sys.stdout.close()
        finally:
            sys.exit(EXIT_OK)
    except KeyboardInterrupt:
        print("\naborted.", file=sys.stderr)
        sys.exit(130)
