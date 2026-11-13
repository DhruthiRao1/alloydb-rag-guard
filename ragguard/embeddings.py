"""Embedders. HashEmbedder is deterministic and offline (tests, demos).
VertexEmbedder calls a Gemini embedding model on Vertex AI."""
from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol, Sequence


class Embedder(Protocol):
    dim: int

    def embed(self, texts: Sequence[str], kind: str = "document") -> list[list[float]]: ...


class HashEmbedder:
    """Feature hashing over words and word pairs, L2-normalised. Texts that share
    vocabulary land close together, which is enough to exercise the store."""

    def __init__(self, dim: int = 256):
        self.dim = dim

    def _one(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        words = re.findall(r"[a-z0-9]+", text.lower())
        for token in words + [a + "_" + b for a, b in zip(words, words[1:])]:
            h = int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big")
            vec[h % self.dim] += 1.0 if (h >> 63) else -1.0
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    def embed(self, texts: Sequence[str], kind: str = "document") -> list[list[float]]:
        return [self._one(t) for t in texts]


class VertexEmbedder:
    """Requires `pip install google-genai` and Application Default Credentials."""

    def __init__(self, project: str, location: str = "us-central1",
                 model: str = "gemini-embedding-001", dim: int = 768, batch_size: int = 50):
        from google import genai                      # imported lazily: optional dependency
        from google.genai import types
        self._client = genai.Client(vertexai=True, project=project, location=location)
        self._types = types
        self.model, self.dim, self.batch_size = model, dim, batch_size

    def embed(self, texts: Sequence[str], kind: str = "document") -> list[list[float]]:
        task = "RETRIEVAL_QUERY" if kind == "query" else "RETRIEVAL_DOCUMENT"
        out: list[list[float]] = []
        for i in range(0, len(texts), self.batch_size):
            resp = self._client.models.embed_content(
                model=self.model, contents=list(texts[i:i + self.batch_size]),
                config=self._types.EmbedContentConfig(task_type=task, output_dimensionality=self.dim))
            out += [list(e.values) for e in resp.embeddings]
        return out
