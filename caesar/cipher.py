"""Caesar cipher core logic.

Pure functions only — no printing, no argument parsing, no I/O. Everything
here is safe to import from a web handler, a notebook, or the CLI.

    >>> encrypt("Attack at dawn!", 3)
    'Dwwdfn dw gdzq!'
    >>> decrypt("Dwwdfn dw gdzq!", 3)
    'Attack at dawn!'

SECURITY: the Caesar cipher is a teaching tool, not encryption. There are only
25 usable keys, so anything it protects can be broken by hand in seconds — as
``brute_force`` in this very module demonstrates. Never use it for real
secrets; use a vetted library such as ``cryptography`` instead.
"""

from __future__ import annotations

from typing import Dict, List, NamedTuple, Sequence

#: Letters in the Latin alphabet the cipher rotates through.
ALPHABET_SIZE = 26

_LOWER_A = ord("a")
_UPPER_A = ord("A")

# Relative frequency of each letter in ordinary English text, as percentages.
# Used only to rank brute-force candidates; it has no effect on encryption.
_ENGLISH_FREQUENCIES: Dict[str, float] = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228,
    "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025,
    "m": 2.406, "n": 6.749, "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987,
    "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150,
    "y": 1.974, "z": 0.074,
}


class Candidate(NamedTuple):
    """One brute-force result: the shift tried and the text it produces.

    ``score`` is a chi-squared distance from English letter frequencies, so
    **lower is more English-like**. It is a hint for ranking guesses, never a
    decision — short or non-English plaintexts will rank badly even when they
    are correct.
    """

    shift: int
    text: str
    score: float


def _validate(text: str, shift: int) -> None:
    """Reject argument types that would otherwise fail confusingly later."""
    if not isinstance(text, str):
        raise TypeError(f"text must be str, got {type(text).__name__}")
    # bool is a subclass of int, so `encrypt(t, True)` would silently shift by
    # 1. That is always a mistake at the call site, so refuse it explicitly.
    if isinstance(shift, bool) or not isinstance(shift, int):
        raise TypeError(f"shift must be int, got {type(shift).__name__}")


def _shift_char(char: str, shift: int) -> str:
    """Rotate one character, leaving anything outside A-Z / a-z untouched.

    Deliberately tests the ASCII ranges rather than ``str.isalpha()``: "é" and
    "Д" are alphabetic to Python but have no place in a 26-letter rotation, so
    they are preserved verbatim like punctuation.
    """
    if "a" <= char <= "z":
        base = _LOWER_A
    elif "A" <= char <= "Z":
        base = _UPPER_A
    else:
        return char
    return chr(base + (ord(char) - base + shift) % ALPHABET_SIZE)


def normalise_shift(shift: int) -> int:
    """Reduce any integer key to the equivalent shift in 0-25.

    Python's ``%`` already returns a non-negative result for a positive
    modulus, so this handles keys larger than 26 (``29 -> 3``) and negative
    keys (``-3 -> 23``) with the same expression.
    """
    return shift % ALPHABET_SIZE


def encrypt(text: str, shift: int) -> str:
    """Encrypt ``text`` by rotating each letter forward ``shift`` places.

    Case is preserved and every non-alphabetic character passes through
    unchanged. Any integer key is accepted; see :func:`normalise_shift`.

    Raises:
        TypeError: If ``text`` is not a ``str`` or ``shift`` is not an ``int``.
    """
    _validate(text, shift)
    offset = normalise_shift(shift)
    if offset == 0:
        # A shift of 0 (or any multiple of 26) is the identity.
        return text
    return "".join(_shift_char(char, offset) for char in text)


def decrypt(text: str, shift: int) -> str:
    """Decrypt ``text`` that was encrypted with ``shift``.

    Rotating backwards by the same key is the exact inverse of
    :func:`encrypt`, so ``decrypt(encrypt(t, k), k) == t`` for every integer k.
    """
    _validate(text, shift)
    return encrypt(text, -shift)


def english_score(text: str) -> float:
    """Chi-squared distance between ``text``'s letter mix and English.

    Lower means more English-like. Returns ``inf`` when there are no letters
    to measure, so such candidates sort last rather than first.
    """
    letters = [char for char in text.lower() if "a" <= char <= "z"]
    if not letters:
        return float("inf")

    total = len(letters)
    score = 0.0
    for letter, percentage in _ENGLISH_FREQUENCIES.items():
        expected = total * percentage / 100.0
        observed = letters.count(letter)
        score += (observed - expected) ** 2 / expected
    return score


def brute_force(
    ciphertext: str, shifts: Sequence[int] | None = None
) -> List[Candidate]:
    """Decrypt ``ciphertext`` with every possible key.

    Args:
        ciphertext: The text to crack.
        shifts: Keys to try. Defaults to 1-25 — every shift that changes the
            text. 0 is excluded because it just returns the input.

    Returns:
        One :class:`Candidate` per shift, in shift order. Sort by ``score`` to
        put the most English-looking guess first.

    Raises:
        TypeError: If ``ciphertext`` is not a ``str``.
    """
    if not isinstance(ciphertext, str):
        raise TypeError(f"ciphertext must be str, got {type(ciphertext).__name__}")

    keys = range(1, ALPHABET_SIZE) if shifts is None else shifts
    candidates = []
    for shift in keys:
        plaintext = decrypt(ciphertext, shift)
        candidates.append(Candidate(shift, plaintext, english_score(plaintext)))
    return candidates


def best_guess(ciphertext: str) -> Candidate:
    """The brute-force candidate whose letter frequencies look most English.

    A convenience wrapper over :func:`brute_force`; treat the result as a
    suggestion to eyeball, not an answer.

    Raises:
        ValueError: If there are no candidates to choose from.
    """
    candidates = brute_force(ciphertext)
    if not candidates:
        raise ValueError("no candidates to choose from")
    return min(candidates, key=lambda candidate: candidate.score)
