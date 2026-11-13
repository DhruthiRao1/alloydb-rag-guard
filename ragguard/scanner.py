"""Scan a document for RAG poisoning before it is indexed.

A poisoned document carries text aimed at the model that will later read it:
instructions to override its rules, hidden text a human reviewer won't see, or
payloads that leak data. The scanner looks at the raw text (to find hiding
techniques) and at a normalised copy (so the hiding doesn't defeat the rules)."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import asdict, dataclass

ZERO_WIDTH = re.compile(r"[​-‏‪-‮⁠-⁤﻿]")
TAG_CHARS = re.compile(r"[\U000e0000-\U000e007f]")       # invisible Unicode "tag" block
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
HIDDEN_STYLE = re.compile(
    r"<[^>]+style\s*=\s*[\"'][^\"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
    r"opacity\s*:\s*0(\.0+)?(?![.\d])|(?<![-\w])color\s*:\s*(#fff(fff)?\b|white\b))[^\"']*[\"'][^>]*>(.*?)</", re.I | re.S)
B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

# (rule id, weight 0-1, pattern) applied to normalised text
TEXT_RULES: list[tuple[str, float, re.Pattern]] = [
    ("instruction_override", 0.8, re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|any)\b.{0,40}"
        r"\b(instruction|prompt|rule|guidance|context)s?\b", re.I | re.S)),
    # Weighted below the quarantine threshold on its own: product specs say things like
    # "the assistant should always greet the user". It tips the balance with other signals.
    ("addressed_to_model", 0.45, re.compile(
        r"\b(ai|assistant|llm|language model|chatbot)\b\s*[,:]?\s*(you\s+)?"
        r"(must|should|shall|will|need to|are required to)\s+(now\s+)?"
        r"(always|never|only|say|tell|respond|reply|recommend|answer|output|reveal|ignore)\b", re.I)),
    ("conditional_answer_steering", 0.6, re.compile(
        r"\b(when|if|whenever)\b.{0,40}\b(asked|asks|summari[sz]|question|user)\b.{0,80}"
        r"\b(always|instead|only)\b.{0,40}\b(say|respond|reply|recommend|answer|tell)\b", re.I | re.S)),
    ("fake_system_message", 0.7, re.compile(
        r"\[\s*(system|assistant|developer)\s*(note|message|prompt|instruction)?\s*\]|"
        r"<\s*/?\s*(system|assistant)\s*>|^\s*(system|assistant)\s*:\s", re.I | re.M)),
    ("prompt_extraction", 0.7, re.compile(
        r"\b(reveal|print|repeat|output|disclose)\b.{0,40}\b(system prompt|hidden prompt|your instructions|api key|credentials)\b",
        re.I | re.S)),
    ("data_exfiltration", 0.8, re.compile(
        r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*=[^)\s]*\)|"
        r"\b(send|post|upload|forward|append)\b.{0,60}\b(conversation|chat history|user data|secrets?|credentials?)\b.{0,60}https?://",
        re.I | re.S)),
]

IMPERATIVE_TO_MODEL = re.compile(r"\b(assistant|ai|model|llm|system|ignore|instruction|respond|reply|say|print)\b", re.I)


@dataclass(frozen=True)
class Finding:
    rule: str
    weight: float
    excerpt: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    risk: float                 # 0-1, combined from finding weights
    findings: tuple
    clean_text: str             # normalised text with hidden content removed

    @property
    def rules(self) -> list[str]:
        return sorted({f.rule for f in self.findings})


def normalise(text: str) -> str:
    """Undo common hiding tricks so rules see what the model would see."""
    text = unicodedata.normalize("NFKC", text)
    text = TAG_CHARS.sub("", ZERO_WIDTH.sub("", text))
    return text


def _excerpt(text: str, start: int, end: int, width: int = 60) -> str:
    snippet = text[max(0, start - 10): min(len(text), max(end, start + width))]
    return re.sub(r"\s+", " ", snippet).strip()[:120]


def _text_findings(text: str, prefix: str = "") -> list[Finding]:
    out = []
    for rule, weight, pattern in TEXT_RULES:
        m = pattern.search(text)
        if m:
            out.append(Finding(prefix + rule, weight, _excerpt(text, m.start(), m.end())))
    return out


def scan(raw: str) -> ScanResult:
    findings: list[Finding] = []

    # 1. Hiding techniques, judged on the raw text.
    zero_width = len(ZERO_WIDTH.findall(raw))
    if zero_width >= 3:
        findings.append(Finding("zero_width_characters", 0.4, f"{zero_width} invisible characters"))
    if TAG_CHARS.search(raw):
        decoded = "".join(chr(ord(c) - 0xE0000) for c in TAG_CHARS.findall(raw) if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        findings.append(Finding("unicode_tag_smuggling", 0.9, decoded[:120] or "invisible tag characters"))
        findings += _text_findings(decoded, "tag:")

    text = normalise(raw)

    for m in HTML_COMMENT.finditer(text):
        if IMPERATIVE_TO_MODEL.search(m.group(1)):
            findings.append(Finding("hidden_html_comment", 0.7, _excerpt(text, m.start(), m.end())))
    for m in HIDDEN_STYLE.finditer(text):
        findings.append(Finding("hidden_styled_text", 0.7, _excerpt(text, m.start(), m.end())))

    # 2. Content rules on normalised text (comments included: the model would read them).
    findings += _text_findings(text)

    # 3. Encoded payloads.
    for token in B64.findall(text):
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        inner = _text_findings(decoded, "base64:")
        if inner:
            findings += inner
            break

    # Combine: independent-evidence style, so several weak signals add up.
    safe = 1.0
    for f in findings:
        safe *= 1 - f.weight
    clean = HIDDEN_STYLE.sub(" ", HTML_COMMENT.sub(" ", text))
    clean = re.sub(r"[ \t]+", " ", clean).strip()
    return ScanResult(round(1 - safe, 3), tuple(findings), clean)
