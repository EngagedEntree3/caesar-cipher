"""Tests for the command line interface.

These drive ``main()`` directly with injected streams rather than spawning a
subprocess, so they run fast and assert on exact output. One end-to-end
subprocess test is included to prove the script really is executable.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import main as cli  # noqa: E402


def run(argv, stdin_text=None):
    """Invoke the CLI and capture what it writes to stdout.

    stderr is captured too — argparse writes usage errors straight to the real
    stderr, which would otherwise scatter noise through the test report on the
    tests that deliberately trigger those errors.
    """
    stdout = io.StringIO()
    stdin = io.StringIO(stdin_text) if stdin_text is not None else None
    with contextlib.redirect_stderr(io.StringIO()):
        status = cli.main(argv, stdin=stdin, stdout=stdout)
    return status, stdout.getvalue()


class TestEncryptCommand(unittest.TestCase):
    def test_encrypts_argument_text(self):
        status, out = run(["encrypt", "Attack at dawn!", "--shift", "3"])
        self.assertEqual(status, 0)
        self.assertEqual(out, "Dwwdfn dw gdzq!\n")

    def test_short_flag(self):
        _, out = run(["encrypt", "abc", "-s", "3"])
        self.assertEqual(out, "def\n")

    def test_negative_shift_on_the_command_line(self):
        # argparse must not mistake "-3" for an option.
        _, out = run(["encrypt", "abc", "-s", "-3"])
        self.assertEqual(out, "xyz\n")

    def test_shift_larger_than_the_alphabet(self):
        _, out = run(["encrypt", "abc", "--shift", "29"])
        self.assertEqual(out, "def\n")

    def test_reads_stdin_when_no_text_argument(self):
        _, out = run(["encrypt", "--shift", "13"], stdin_text="Hello, World!\n")
        self.assertEqual(out, "Uryyb, Jbeyq!\n")

    def test_only_one_trailing_newline_is_stripped_from_stdin(self):
        _, out = run(["encrypt", "--shift", "0"], stdin_text="a\n\n")
        self.assertEqual(out, "a\n\n")

    def test_empty_stdin(self):
        status, out = run(["encrypt", "--shift", "5"], stdin_text="")
        self.assertEqual(status, 0)
        self.assertEqual(out, "\n")


class TestDecryptCommand(unittest.TestCase):
    def test_decrypts_argument_text(self):
        _, out = run(["decrypt", "Dwwdfn dw gdzq!", "--shift", "3"])
        self.assertEqual(out, "Attack at dawn!\n")

    def test_round_trip_through_the_cli(self):
        _, encrypted = run(["encrypt", "Meet me at noon", "-s", "17"])
        _, decrypted = run(["decrypt", encrypted.rstrip("\n"), "-s", "17"])
        self.assertEqual(decrypted, "Meet me at noon\n")

    def test_reads_stdin(self):
        _, out = run(["decrypt", "-s", "13"], stdin_text="Uryyb\n")
        self.assertEqual(out, "Hello\n")


class TestCrackCommand(unittest.TestCase):
    def test_outputs_twenty_five_lines(self):
        _, out = run(["crack", "Dwwdfn dw gdzq"])
        self.assertEqual(len(out.strip().split("\n")), 25)

    def test_includes_the_real_plaintext(self):
        _, out = run(["crack", "Wkh txlfn eurzq ira"])
        self.assertIn("The quick brown fox", out)

    def test_lines_are_numbered_by_shift(self):
        _, out = run(["crack", "abc"])
        # splitlines, not strip().split(): stripping would eat the leading
        # space that right-aligns single-digit shifts, which is the thing
        # being asserted.
        lines = out.splitlines()
        self.assertEqual(len(lines), 25)
        self.assertTrue(lines[0].startswith(" 1  "), repr(lines[0]))
        self.assertTrue(lines[-1].startswith("25  "), repr(lines[-1]))

    def test_rank_puts_the_most_english_result_first(self):
        _, out = run(
            ["crack", "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj", "--rank"]
        )
        first = out.strip().split("\n")[0]
        self.assertIn("The quick brown fox jumps over the lazy dog", first)

    def test_rank_shows_a_score_column(self):
        _, ranked = run(["crack", "Wkh txlfn eurzq ira", "--rank"])
        _, plain = run(["crack", "Wkh txlfn eurzq ira"])
        self.assertNotEqual(ranked.split("\n")[0], plain.split("\n")[0])

    def test_top_limits_the_output(self):
        _, out = run(["crack", "Dwwdfn dw gdzq", "--top", "3"])
        self.assertEqual(len(out.strip().split("\n")), 3)

    def test_top_combines_with_rank(self):
        _, out = run(
            ["crack", "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj", "-r", "-t", "1"]
        )
        self.assertEqual(len(out.strip().split("\n")), 1)
        self.assertIn("The quick brown fox", out)

    def test_top_below_one_is_a_usage_error(self):
        with self.assertRaises(SystemExit) as caught:
            run(["crack", "abc", "--top", "0"])
        self.assertEqual(caught.exception.code, 2)

    def test_reads_stdin(self):
        _, out = run(["crack"], stdin_text="Wkh txlfn eurzq ira\n")
        self.assertIn("The quick brown fox", out)


class TestArgumentErrors(unittest.TestCase):
    def test_missing_command_exits_with_usage_error(self):
        with self.assertRaises(SystemExit) as caught:
            run([])
        self.assertEqual(caught.exception.code, 2)

    def test_unknown_command_exits_with_usage_error(self):
        with self.assertRaises(SystemExit) as caught:
            run(["rot13", "abc"])
        self.assertEqual(caught.exception.code, 2)

    def test_encrypt_without_shift_exits_with_usage_error(self):
        with self.assertRaises(SystemExit) as caught:
            run(["encrypt", "abc"])
        self.assertEqual(caught.exception.code, 2)

    def test_non_integer_shift_exits_with_usage_error(self):
        with self.assertRaises(SystemExit) as caught:
            run(["encrypt", "abc", "--shift", "three"])
        self.assertEqual(caught.exception.code, 2)


class TestHelpers(unittest.TestCase):
    def test_read_text_prefers_the_argument(self):
        self.assertEqual(cli.read_text("given", io.StringIO("ignored")), "given")

    def test_read_text_falls_back_to_the_stream(self):
        self.assertEqual(cli.read_text(None, io.StringIO("piped\n")), "piped")

    def test_read_text_keeps_an_empty_argument(self):
        # An explicit empty string is a real input, not a missing one.
        self.assertEqual(cli.read_text("", io.StringIO("piped")), "")

    def test_parser_builds_without_error(self):
        parser = cli.build_parser()
        self.assertEqual(parser.prog, "main.py")


class TestEndToEnd(unittest.TestCase):
    """Prove the script actually runs as a program, not just as an import."""

    def test_subprocess_round_trip(self):
        encrypted = subprocess.run(
            [sys.executable, str(ROOT / "main.py"), "encrypt", "-s", "5"],
            input="Ship it\n",
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        decrypted = subprocess.run(
            [sys.executable, str(ROOT / "main.py"), "decrypt", "-s", "5"],
            input=encrypted,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertEqual(decrypted, "Ship it\n")

    def test_subprocess_usage_error_exit_code(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "main.py"), "encrypt", "abc"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("required", result.stderr.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
