import random
import secrets

import pytest

from attacks import predict_tokens
from secure_input import templates, tokens


def test_clone_predicts_every_following_token():
    victim = random.Random()                  # seeded from os.urandom
    observed = [predict_tokens.weak_token(victim) for _ in range(predict_tokens.TOKENS_NEEDED)]
    clone = predict_tokens.clone_from_tokens(observed)
    for _ in range(200):
        assert predict_tokens.weak_token(clone) == predict_tokens.weak_token(victim)


def test_module_level_random_is_also_clonable():
    """No explicit Random() instance and no seed: the default generator falls the same way."""
    observed = [predict_tokens.weak_token() for _ in range(predict_tokens.TOKENS_NEEDED)]
    clone = predict_tokens.clone_from_tokens(observed)
    assert predict_tokens.weak_token(clone) == predict_tokens.weak_token()


def test_624_raw_outputs_reproduce_the_625th():
    g = random.Random(7)
    outs = [g.getrandbits(32) for _ in range(625)]
    c = random.Random()
    c.setstate((3, tuple(predict_tokens.untemper(o) for o in outs[:624]) + (624,), None))
    assert c.getrandbits(32) == outs[624]


def test_too_few_tokens():
    with pytest.raises(ValueError):
        predict_tokens.clone_from_tokens(["00" * 16] * 10)


def test_attack_fails_on_secrets():
    result = predict_tokens.run(predict=20)
    assert result["weak_correct"] == 20
    assert result["strong_correct"] == 0


def test_statistics_cannot_tell_them_apart():
    weak = [random.randint(1, 100) for _ in range(5000)]
    strong = [secrets.randbelow(100) + 1 for _ in range(5000)]
    for vals in (weak, strong):
        assert tokens.shannon_entropy(vals) > 6.5            # max is log2(100) = 6.64
        assert tokens.chi_square_uniform(vals, 1, 100) < 160  # loose bound, avoids flaky runs


def test_session_tokens():
    seen = {tokens.session_token() for _ in range(500)}
    assert len(seen) == 500 and min(map(len, seen)) >= 43


def test_reset_token_stored_hashed_and_expires():
    token, record = tokens.issue_reset_token(now=1000.0)
    assert token not in record.token_sha256
    assert tokens.check_reset_token(token, record, now=1000.0 + 60)
    assert not tokens.check_reset_token(token, record, now=1000.0 + tokens.RESET_LIFETIME_SECONDS + 1)
    assert not tokens.check_reset_token(token + "x", record, now=1001.0)


def test_python_template_injection():
    note = templates.Notification("Maria")
    attack = "{n.__init__.__globals__[CONFIG].db_password}"
    assert templates.unsafe_greeting(attack, note) == templates.CONFIG.db_password
    assert templates.CONFIG.db_password not in templates.safe_greeting(attack, note)
