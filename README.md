# secure-input-kit

Input handling for a small healthcare portal: allowlist validation, parameterised SQL, XSS-safe rendering, safe format strings and unpredictable tokens. Each defence sits next to the attack it stops, and the first version of the code is kept in `legacy/` with tests that show what was wrong with it.

Standard library only. 92 tests, CI on Linux and Windows.

```
$ python -m attacks.predict_tokens
observed 156 tokens from random.getrandbits(128)
  predicted next token : 6607652ad5c01f552d36afc2233d1ab7
  actual next token    : 6607652ad5c01f552d36afc2233d1ab7
  correct predictions  : 10/10
same attack on secrets.token_hex(16): 0/10
```

## Three things the first version got wrong

### 1. "Use secrets, because a seeded generator is guessable" undersold it

The first version compared `random` with `secrets` by seeding `random` with the current time and showing that the same seed gives the same tokens. True, but it suggests the danger is the seed.

You don't need the seed. Python's `random` is a Mersenne Twister (MT19937). Each output is a reversible transform of one word of its internal state, and the state is 624 words. A 128-bit token is four outputs, so **156 tokens reveal the whole state** and every token after that can be computed. [`attacks/predict_tokens.py`](attacks/predict_tokens.py) does this against a generator seeded from `os.urandom`, using only tokens the attacker would see from its own logins. It predicts 10 of the next 10 tokens exactly, and 0 of 10 when the tokens come from `secrets`.

The randomness statistics in the demo (chi-square, Shannon entropy) show `random` and `secrets` as equally good. Statistics can't tell a predictable generator from a secure one.

*Scope:* the first version's session tokens used `random.choice` over 36 characters, which exposes only a few bits per output and skips some outputs, so this exact attack doesn't apply. The attack targets the `getrandbits` form that the seed comparison used. The fix is the same for both: `secrets`.

### 2. The email validator rejected real addresses

The validator had a good anchored regex, plus a substring blacklist run first as "extra XSS protection": `<`, `>`, `script`, `javascript:`, `onerror`, `'`, `;` and so on.

| Address | v1 | v2 |
|---|---|---|
| `prescriptions@pharmacy.ca` | reject (contains "script") | accept |
| `transcription@clinic.com` | reject (contains "script") | accept |
| `o'brien@clinic.ca` | reject (contains `'`) | accept |
| `<script>alert(1)</script>@evil.com` | reject | reject |

The regex already refused `<`, `>`, `"` and `;`, so the blacklist only added false rejections. For a healthcare portal, the pharmacy's prescriptions inbox and the transcription team are not edge cases. v2 is the regex alone, with `'` allowed in the local part. An apostrophe is safe because SQL uses parameters and HTML output is encoded. **Validation checks shape. Parameterised queries and output encoding are what stop injection.** The tests check that v2 still rejects everything v1 rejected for containing markup.

### 3. The XSS sanitizer deleted words and missed a link

The first version stripped "dangerous" patterns from comments before storing them:

```
in : Dose was one = 5 ml twice a day
out: Dose was  5 ml twice a day                      <- "one =" matched on\w+=

in : <a href="jav&#x61;script:alert(document.cookie)">see my results</a>
out: <a href="jav&#x61;script:alert(document.cookie)">see my results</a>   <- unchanged
```

Browsers decode `&#x61;` inside attributes, so that link runs `javascript:` when clicked. The portal itself was still safe, because `html.escape()` ran on every comment after the sanitizer. **The escaping did the work. The sanitizer only corrupted what patients wrote**, and it would have been an XSS hole in any view that trusted it without escaping.

v2 stores comments as written, encodes them on output, and keeps the pattern list only for `flag_comment()`, which reports matches (after decoding entities) without changing the text. It also adds one thing escaping can't do: `html.escape("javascript:alert(1)")` returns the string unchanged, so user-supplied links go through a scheme allowlist (`http`, `https`, `mailto`) that also catches `java\tscript:` and entity-encoded schemes.

## What's inside

| Module | Covers | Attack shown |
|---|---|---|
| [`secure_input/validators.py`](secure_input/validators.py) | email, filename and path allowlists; normalise, then check the path is inside the base dir | `../`, `..\`, absolute paths, null bytes, `reports/.env`, the `startswith` sibling-folder bug, symlinks |
| [`secure_input/sql.py`](secure_input/sql.py) | parameterised queries, PBKDF2-SHA256 at 600,000 iterations, constant-time compare | tautology, `admin' --` login bypass, UNION dump of password hashes, stacked query |
| [`secure_input/xss.py`](secure_input/xss.py) | output encoding, link scheme allowlist, flag-don't-modify review | `<script>`, `<img onerror>`, markup in author names, `javascript:` links |
| [`secure_input/templates.py`](secure_input/templates.py), [`c/format_demo.c`](c/format_demo.c) | fixed format strings | `printf(user_input)` leaking stack values; Python `str.format` reading a secret via `__globals__` |
| [`secure_input/tokens.py`](secure_input/tokens.py) | `secrets` tokens; reset tokens stored as SHA-256 with a 15-minute expiry | |
| [`attacks/predict_tokens.py`](attacks/predict_tokens.py) | MT19937 state recovery from observed tokens | session token prediction |
| [`legacy/`](legacy) | first versions of the email validator and comment sanitizer | regression tests for the flaws above |

Full demo output: [`docs/demo_output.txt`](docs/demo_output.txt)

## Run it

```bash
python -m secure_input            # everything
python -m secure_input v1         # just the first-version comparisons
python -m secure_input tokens     # validation | sql | xss | format | tokens
python -m attacks.predict_tokens

pip install pytest && pytest      # 92 tests

gcc -Wall -Wno-format-security -o format_demo c/format_demo.c
./format_demo "Patient %x %x %x %x"
```

## Not covered

A real portal would also use a templating engine with auto-escaping on (Jinja2, Django templates) rather than f-strings, a Content-Security-Policy as a second layer against XSS, a database account with only the privileges the app needs, and rate limiting on login and reset. The sample data is invented.

## License

MIT
