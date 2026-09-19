"""Tests for the core cipher logic.

Run from the project root:

    ./run_tests.sh
    python3 -m unittest discover -s tests -t . -v
"""

from __future__ import annotations

import string
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from caesar.cipher import (  # noqa: E402
    ALPHABET_SIZE,
    Candidate,
    best_guess,
    brute_force,
    decrypt,
    encrypt,
    english_score,
    normalise_shift,
)


class TestEncrypt(unittest.TestCase):
    def test_basic_lowercase_shift(self):
        self.assertEqual(encrypt("abc", 3), "def")

    def test_basic_uppercase_shift(self):
        self.assertEqual(encrypt("ABC", 3), "DEF")

    def test_case_is_preserved(self):
        self.assertEqual(encrypt("AbC", 3), "DeF")
        self.assertEqual(encrypt("Attack at dawn", 3), "Dwwdfn dw gdzq")

    def test_wraps_around_the_end_of_the_alphabet(self):
        self.assertEqual(encrypt("xyz", 3), "abc")
        self.assertEqual(encrypt("XYZ", 3), "ABC")

    def test_wraps_around_backwards(self):
        self.assertEqual(encrypt("abc", -3), "xyz")
        self.assertEqual(encrypt("ABC", -3), "XYZ")

    def test_shift_of_one_on_the_boundary_letters(self):
        self.assertEqual(encrypt("z", 1), "a")
        self.assertEqual(encrypt("Z", 1), "A")
        self.assertEqual(encrypt("a", -1), "z")


class TestNonAlphabeticCharacters(unittest.TestCase):
    def test_spaces_and_punctuation_are_untouched(self):
        self.assertEqual(encrypt("a-b c!", 1), "b-c d!")

    def test_digits_are_not_shifted(self):
        self.assertEqual(encrypt("abc123", 3), "def123")

    def test_symbol_only_text_is_unchanged(self):
        symbols = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~ \t\n"
        self.assertEqual(encrypt(symbols, 7), symbols)

    def test_non_ascii_letters_are_preserved_verbatim(self):
        # These are alphabetic to Python but have no place in a 26-letter
        # rotation, so they must pass through like punctuation.
        for sample in ("é", "ñ", "Д", "日本語", "ß", "Ω"):
            with self.subTest(sample=sample):
                self.assertEqual(encrypt(sample, 5), sample)

    def test_mixed_ascii_and_non_ascii(self):
        self.assertEqual(encrypt("café", 1), "dbgé")

    def test_emoji_are_preserved(self):
        self.assertEqual(encrypt("hi 🙂", 1), "ij 🙂")


class TestKeyNormalisation(unittest.TestCase):
    def test_zero_shift_is_the_identity(self):
        self.assertEqual(encrypt("Hello, World!", 0), "Hello, World!")

    def test_full_rotation_is_the_identity(self):
        for multiple in (26, 52, 260, -26, -52):
            with self.subTest(shift=multiple):
                self.assertEqual(encrypt("Hello, World!", multiple), "Hello, World!")

    def test_keys_larger_than_the_alphabet_wrap(self):
        self.assertEqual(encrypt("abc", 29), encrypt("abc", 3))
        self.assertEqual(encrypt("abc", 105), encrypt("abc", 105 % ALPHABET_SIZE))

    def test_negative_keys_wrap(self):
        self.assertEqual(encrypt("abc", -3), encrypt("abc", 23))
        self.assertEqual(encrypt("abc", -29), encrypt("abc", -3))

    def test_very_large_keys(self):
        self.assertEqual(encrypt("abc", 10**6 + 3), encrypt("abc", (10**6 + 3) % 26))
        self.assertEqual(encrypt("abc", -(10**6) - 3), encrypt("abc", (-(10**6) - 3) % 26))

    def test_normalise_shift_returns_zero_to_twentyfive(self):
        for shift in range(-100, 101):
            with self.subTest(shift=shift):
                self.assertIn(normalise_shift(shift), range(ALPHABET_SIZE))

    def test_normalise_shift_known_values(self):
        self.assertEqual(normalise_shift(3), 3)
        self.assertEqual(normalise_shift(29), 3)
        self.assertEqual(normalise_shift(-3), 23)
        self.assertEqual(normalise_shift(0), 0)
        self.assertEqual(normalise_shift(26), 0)


class TestDecrypt(unittest.TestCase):
    def test_decrypt_reverses_encrypt(self):
        self.assertEqual(decrypt("def", 3), "abc")

    def test_round_trip_for_every_key(self):
        message = "The quick brown Fox jumps over 13 lazy dogs! (really)"
        for shift in range(-60, 61):
            with self.subTest(shift=shift):
                self.assertEqual(decrypt(encrypt(message, shift), shift), message)

    def test_round_trip_preserves_the_full_ascii_alphabet(self):
        message = string.ascii_letters + string.digits + string.punctuation
        for shift in (1, 7, 13, 25, 26, -13):
            with self.subTest(shift=shift):
                self.assertEqual(decrypt(encrypt(message, shift), shift), message)

    def test_rot13_is_its_own_inverse(self):
        self.assertEqual(encrypt(encrypt("Hello", 13), 13), "Hello")


class TestEdgeCases(unittest.TestCase):
    def test_empty_string(self):
        self.assertEqual(encrypt("", 5), "")
        self.assertEqual(decrypt("", 5), "")

    def test_single_character(self):
        self.assertEqual(encrypt("a", 1), "b")

    def test_long_input_is_handled(self):
        message = "abc" * 10_000
        self.assertEqual(decrypt(encrypt(message, 11), 11), message)

    def test_whitespace_only(self):
        self.assertEqual(encrypt("   \t\n", 4), "   \t\n")


class TestInputValidation(unittest.TestCase):
    def test_non_string_text_is_rejected(self):
        for bad in (None, 42, b"bytes", ["a"], {"a": 1}):
            with self.subTest(value=bad):
                with self.assertRaises(TypeError):
                    encrypt(bad, 3)
                with self.assertRaises(TypeError):
                    decrypt(bad, 3)

    def test_non_integer_shift_is_rejected(self):
        for bad in (None, "3", 3.0, [3]):
            with self.subTest(value=bad):
                with self.assertRaises(TypeError):
                    encrypt("abc", bad)

    def test_boolean_shift_is_rejected(self):
        # bool subclasses int, so True would silently mean "shift by 1".
        with self.assertRaises(TypeError):
            encrypt("abc", True)
        with self.assertRaises(TypeError):
            encrypt("abc", False)

    def test_error_messages_name_the_offending_type(self):
        with self.assertRaisesRegex(TypeError, "text must be str, got int"):
            encrypt(1, 1)
        with self.assertRaisesRegex(TypeError, "shift must be int, got str"):
            encrypt("a", "1")

    def test_brute_force_rejects_non_string(self):
        with self.assertRaises(TypeError):
            brute_force(42)


class TestBruteForce(unittest.TestCase):
    def test_returns_twenty_five_candidates(self):
        self.assertEqual(len(brute_force("Dwwdfn")), 25)

    def test_covers_shifts_one_through_twentyfive(self):
        shifts = [candidate.shift for candidate in brute_force("Dwwdfn")]
        self.assertEqual(shifts, list(range(1, 26)))

    def test_contains_the_correct_plaintext(self):
        candidates = brute_force(encrypt("Attack at dawn", 7))
        texts = [candidate.text for candidate in candidates]
        self.assertIn("Attack at dawn", texts)

    def test_correct_plaintext_sits_at_the_right_shift(self):
        candidates = brute_force(encrypt("Attack at dawn", 7))
        match = next(c for c in candidates if c.shift == 7)
        self.assertEqual(match.text, "Attack at dawn")

    def test_results_are_candidate_named_tuples(self):
        candidate = brute_force("abc")[0]
        self.assertIsInstance(candidate, Candidate)
        self.assertEqual(candidate.shift, 1)
        self.assertEqual(candidate.text, decrypt("abc", 1))

    def test_custom_shift_sequence(self):
        candidates = brute_force("abc", shifts=[1, 5])
        self.assertEqual([c.shift for c in candidates], [1, 5])

    def test_empty_ciphertext_still_returns_every_shift(self):
        candidates = brute_force("")
        self.assertEqual(len(candidates), 25)
        self.assertTrue(all(c.text == "" for c in candidates))


class TestEnglishScoring(unittest.TestCase):
    def test_english_text_scores_better_than_scrambled(self):
        english = "the quick brown fox jumps over the lazy dog"
        scrambled = encrypt(english, 13)
        self.assertLess(english_score(english), english_score(scrambled))

    def test_text_without_letters_scores_infinity(self):
        self.assertEqual(english_score("12345 !!!"), float("inf"))
        self.assertEqual(english_score(""), float("inf"))

    def test_best_guess_finds_the_real_plaintext(self):
        plaintext = "It was the best of times, it was the worst of times"
        for shift in (3, 11, 19, 25):
            with self.subTest(shift=shift):
                guess = best_guess(encrypt(plaintext, shift))
                self.assertEqual(guess.shift, shift)
                self.assertEqual(guess.text, plaintext)

    def test_best_guess_returns_a_candidate(self):
        self.assertIsInstance(best_guess("Dwwdfn dw gdzq"), Candidate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
