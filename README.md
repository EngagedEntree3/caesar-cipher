# Caesar Cipher Tool

A command-line Caesar cipher: encrypt, decrypt, and crack ciphertext when the
key is unknown. Pure Python standard library — no dependencies, no install step.

```
$ ./main.py encrypt "Attack at dawn!" --shift 3
Dwwdfn dw gdzq!

$ ./main.py decrypt "Dwwdfn dw gdzq!" --shift 3
Attack at dawn!

$ ./main.py crack "Dwwdfn dw gdzq!" --rank --top 3
 3      33.1  Attack at dawn!
18      43.5  Leelnv le olhy!
11      47.1  Sllsuc sl vsof!
```

> **This is not encryption.** The Caesar cipher has 25 usable keys, and the
> `crack` command in this very tool breaks any message in milliseconds. It is
> a teaching tool. Never use it to protect anything real — use a vetted
> library such as [`cryptography`](https://cryptography.io) instead.

## Layout

```
caesar-cipher/
├── caesar/
│   ├── __init__.py      # public API re-exports
│   └── cipher.py        # core logic — pure functions, no I/O
├── main.py              # CLI entry point — argparse, stdin/stdout, formatting
├── tests/
│   ├── test_cipher.py   # 43 tests for the core
│   └── test_cli.py      # 29 tests for the CLI
├── run_tests.sh         # single-command test runner
└── Makefile             # make test / verbose / coverage / demo / clean
```

The split is the point: `cipher.py` never prints and never reads argv, so it
can be imported from a web handler or a notebook unchanged. `main.py` holds
every piece of terminal-facing behaviour.

## Usage

### Encrypt and decrypt

```bash
./main.py encrypt "Attack at dawn!" --shift 3
./main.py decrypt "Dwwdfn dw gdzq!" -s 3
```

Any integer works as a key. Keys are reduced modulo 26, so oversized and
negative keys behave exactly as you would expect:

```bash
./main.py encrypt "abc" -s 29     # def   (29 ≡ 3)
./main.py encrypt "abc" -s -3     # xyz   (-3 ≡ 23)
./main.py encrypt "abc" -s 26     # abc   (identity)
```

### Crack an unknown key

```bash
./main.py crack "Wkh txlfn eurzq ira"          # all 25 shifts
./main.py crack "Wkh txlfn eurzq ira" --rank   # most English-like first
./main.py crack "Wkh txlfn eurzq ira" -r -t 5  # just the top 5
```

`--rank` scores each candidate by chi-squared distance from English letter
frequencies — **lower is more English-like** — and sorts on it. It is a hint,
not an answer: short messages and non-English plaintext will rank poorly even
when they are correct. Without `--rank` you get all 25 in shift order.

### Piping

Omit the text argument and the tool reads stdin, so it composes with other
commands and handles files:

```bash
cat secret.txt | ./main.py encrypt --shift 13 > secret.enc
./main.py decrypt --shift 13 < secret.enc
./main.py crack < secret.enc | head -5
```

Exactly one trailing newline is stripped from stdin — the one your shell or
editor adds. Any other whitespace is preserved, because leading spaces and
blank lines can be part of the message.

### As a library

```python
from caesar import encrypt, decrypt, brute_force, best_guess

encrypt("Attack at dawn!", 3)      # 'Dwwdfn dw gdzq!'
decrypt("Dwwdfn dw gdzq!", 3)      # 'Attack at dawn!'

for shift, text, score in brute_force("Dwwdfn dw gdzq!"):
    print(shift, text)

best_guess("Dwwdfn dw gdzq!")      # Candidate(shift=3, text='Attack at dawn!', ...)
```

## Behaviour

| Input | Result |
|---|---|
| `abc` shift 3 | `def` |
| `xyz` shift 3 | `abc` — wraps around |
| `AbC` shift 3 | `DeF` — case preserved |
| `abc123!` shift 3 | `def123!` — non-letters untouched |
| `café` shift 1 | `dbgé` — non-ASCII letters untouched |
| any text, shift 0 / 26 / 52 | unchanged |
| `abc` shift -3 | `xyz` |

**Non-ASCII letters pass through unchanged.** `é` and `Д` are alphabetic to
Python but have no position in a 26-letter rotation, so the code tests the
`a`–`z` / `A`–`Z` ranges directly rather than using `str.isalpha()`. This is a
deliberate choice, and it keeps `decrypt(encrypt(t, k), k) == t` true for every
possible string.

### Errors

`encrypt` and `decrypt` raise `TypeError` for a non-`str` text or a non-`int`
shift. Booleans are rejected too — `bool` subclasses `int`, so `encrypt(t, True)`
would otherwise silently shift by 1, which is always a bug at the call site.

The CLI exits `0` on success and `2` on a usage error (missing subcommand,
missing `--shift`, a non-integer key), so it can gate a shell script.

## Tests

```bash
./run_tests.sh          # or: make test
./run_tests.sh -v       # per-test output
make coverage           # needs `pip install coverage`
```

72 tests, no dependencies. They cover encryption, decryption, round-trips
across keys −60 to 60, wrap-around at both ends, oversized and negative and
million-scale keys, case preservation, punctuation, digits, emoji, non-ASCII
letters, empty and whitespace-only input, type validation, all three
subcommands, stdin handling, argument errors and exit codes — plus a
subprocess test that runs `main.py` as a real program rather than an import.

`-k` filtering is case-sensitive: a bare word matches test *method* names
(`-k test_top`), while the glob form matches the full id (`-k '*Crack*'`).
