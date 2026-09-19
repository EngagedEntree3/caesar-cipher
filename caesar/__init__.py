"""Caesar cipher toolkit.

    >>> from caesar import encrypt, decrypt
    >>> decrypt(encrypt("hello", 7), 7)
    'hello'

The Caesar cipher is an educational cipher with 25 usable keys. It provides no
real confidentiality — see the note in :mod:`caesar.cipher`.
"""

from .cipher import (
    ALPHABET_SIZE,
    Candidate,
    best_guess,
    brute_force,
    decrypt,
    encrypt,
    english_score,
    normalise_shift,
)

__all__ = [
    "encrypt",
    "decrypt",
    "brute_force",
    "best_guess",
    "english_score",
    "normalise_shift",
    "Candidate",
    "ALPHABET_SIZE",
]

__version__ = "1.0.0"
