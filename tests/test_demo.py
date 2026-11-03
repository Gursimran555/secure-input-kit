from secure_input.__main__ import main


def test_demo_runs(capsys):
    assert main(["all"]) == 0
    out = capsys.readouterr().out
    assert "10/10 next tokens predicted exactly" in out
    assert "Same attack on secrets.token_hex(16): 0/10" in out


def test_unknown_section():
    assert main(["nope"]) == 2
