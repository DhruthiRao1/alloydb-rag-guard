import pytest

from ragguard.pipeline import QUARANTINE_THRESHOLD, chunk
from ragguard.scanner import normalise, scan

from .corpus import BENIGN, POISONED


@pytest.mark.parametrize("name", sorted(POISONED))
def test_poisoned_documents_are_quarantined(name):
    result = scan(POISONED[name])
    assert result.risk >= QUARANTINE_THRESHOLD, (name, result.findings)


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_benign_documents_pass(name):
    result = scan(BENIGN[name])
    assert result.risk < QUARANTINE_THRESHOLD, (name, result.findings)


def test_expected_rules_fire():
    assert "hidden_html_comment" in scan(POISONED["html_comment"]).rules
    assert "hidden_styled_text" in scan(POISONED["hidden_css"]).rules
    assert "unicode_tag_smuggling" in scan(POISONED["unicode_tags"]).rules
    assert any(r.startswith("base64:") for r in scan(POISONED["base64"]).rules)
    assert "data_exfiltration" in scan(POISONED["exfil_image"]).rules


def test_clean_text_drops_hidden_content():
    clean = scan(POISONED["hidden_css"]).clean_text
    assert "5 stars" not in clean and "3 stars" in clean
    assert "never accepted" not in scan(POISONED["html_comment"]).clean_text
    assert "​" not in scan(POISONED["zero_width_split"]).clean_text


def test_normalise_handles_fullwidth_and_zero_width():
    assert normalise("ｉｇｎｏｒｅ pre​vious") == "ignore previous"


def test_chunking():
    text = "\n\n".join(["para " + "x" * 300] * 5) + "\n\n" + "y" * 2000
    chunks = chunk(text, max_chars=800)
    assert all(len(c) <= 800 for c in chunks)
    assert "".join(chunks).count("x") == 1500 and "".join(chunks).count("y") == 2000
    assert chunk("   ") == []
