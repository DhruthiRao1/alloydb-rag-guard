"""Ingest: scan -> chunk -> embed -> store. Retrieval: embed -> search active only."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional, Sequence

from .embeddings import Embedder
from .scanner import scan
from .store import PgVectorStore

QUARANTINE_THRESHOLD = 0.5
MAX_DOCUMENT_CHARS = 2_000_000


@dataclass(frozen=True)
class IngestResult:
    document_id: str
    status: str          # active | quarantined | unchanged
    risk: float
    rules: list
    chunks: int


def chunk(text: str, max_chars: int = 800) -> list[str]:
    """Pack paragraphs into chunks; split any oversized paragraph on whitespace."""
    pieces: list[str] = []
    for para in (p.strip() for p in text.split("\n\n")):
        while len(para) > max_chars:
            cut = para.rfind(" ", 0, max_chars)
            cut = cut if cut > 0 else max_chars
            pieces.append(para[:cut].strip())
            para = para[cut:].strip()
        if para:
            pieces.append(para)
    chunks: list[str] = []
    for piece in pieces:
        if chunks and len(chunks[-1]) + len(piece) + 2 <= max_chars:
            chunks[-1] += "\n\n" + piece
        else:
            chunks.append(piece)
    return chunks


class Pipeline:
    def __init__(self, store: PgVectorStore, embedder: Embedder,
                 threshold: float = QUARANTINE_THRESHOLD):
        if embedder.dim != store.dim:
            raise ValueError("embedder and store dimensions differ")
        self.store, self.embedder, self.threshold = store, embedder, threshold

    def ingest(self, doc_id: str, source: str, text: str) -> IngestResult:
        if not doc_id or not source:
            raise ValueError("doc_id and source are required")
        if not text.strip():
            raise ValueError("document is empty")
        if len(text) > MAX_DOCUMENT_CHARS:
            raise ValueError("document too large")
        sha = hashlib.sha256(text.encode()).hexdigest()
        existing = self.store.get_document(doc_id)
        if existing and existing["sha256"] == sha:
            # Unchanged content keeps its status, including a human's release or rejection.
            return IngestResult(doc_id, "unchanged", existing["risk"], [], 0)

        # The whole document is scanned before chunking, so an attack can't hide
        # by straddling a chunk boundary. Changed content is always re-scanned.
        result = scan(text)
        status = "quarantined" if result.risk >= self.threshold else "active"
        chunks = chunk(result.clean_text) or [result.clean_text]
        embeddings = self.embedder.embed(chunks, kind="document")
        self.store.upsert_document(doc_id, source, sha, status, result.risk,
                                   [f.to_dict() for f in result.findings], chunks, embeddings)
        return IngestResult(doc_id, status, result.risk, result.rules, len(chunks))

    def search(self, query: str, k: int = 5, sources: Optional[Sequence[str]] = None) -> list[dict]:
        if not query.strip():
            raise ValueError("query is empty")
        [vec] = self.embedder.embed([query], kind="query")
        return self.store.search(vec, k, sources)
