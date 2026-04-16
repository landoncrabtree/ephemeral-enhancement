"""Tests for the Scytale transposition cipher stage."""

from stages.scytale import scytale_decrypt


def test_scytale_this_is_a_message():
    """User-provided test: 'TIMGHSEEI S SAS   A ' -> 'THIS IS A MESSAGE   ' at 5 cols."""
    ct = "TIMGHSEEI S SAS   A "
    result = scytale_decrypt(ct, 5)
    assert result == "THIS IS A MESSAGE   "


def test_scytale_secret_hidden_message():
    """User-provided test: 'SteseHnsci/ardMgedee' -> 'SecretHidden/Message' at 5 cols."""
    ct = "SteseHnsci/ardMgedee"
    result = scytale_decrypt(ct, 5)
    assert result == "SecretHidden/Message"


def test_scytale_identity_at_1():
    """With 1 column (or >= len), should return the original text."""
    text = "Hello"
    assert scytale_decrypt(text, 1) == text
    assert scytale_decrypt(text, 5) == text


def test_scytale_two_columns():
    """Basic 2-column scytale."""
    # Encrypt "ABCDEF" with 2 cols: grid 3x2
    # A B    read col-by-col: ACE BDF -> "ACEBDF"
    # C D
    # E F
    ct = "ACEBDF"
    result = scytale_decrypt(ct, 2)
    assert result == "ABCDEF"
