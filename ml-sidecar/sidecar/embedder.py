"""Deterministic, dependency-free fallback embedder (DESIGN §9.3).

Feature-hashing bag-of-tokens into a fixed-dimension, L2-normalized vector.
This mirrors the Rust ``HashingEmbedder`` so the sidecar is usable with no
model download. The production path swaps this for a sentence-transformer
(e.g. SecureBERT) when the ``model`` extra is installed.
"""

from __future__ import annotations

import hashlib
import math
from typing import List

DEFAULT_DIM = 128


def embed(text: str, dim: int = DEFAULT_DIM) -> List[float]:
    """Embed a text string into a unit-length vector of length ``dim``."""
    vec = [0.0] * dim
    for token in text.lower().split():
        h = int(hashlib.sha1(token.encode("utf-8")).hexdigest(), 16)
        bucket = h % dim
        sign = 1.0 if (h >> 33) & 1 == 0 else -1.0
        vec[bucket] += sign
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0.0:
        vec = [x / norm for x in vec]
    return vec


class HashingEmbedder:
    """Class wrapper so a real model can be dropped in behind the same API."""

    def __init__(self, dim: int = DEFAULT_DIM) -> None:
        self.dim = dim

    def embed(self, text: str) -> List[float]:
        return embed(text, self.dim)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]


def load_embedder() -> "HashingEmbedder":
    """Return the best available embedder.

    Tries a real sentence-transformer first; falls back to hashing so the
    sidecar always starts.
    """
    try:  # pragma: no cover - exercised only when the model extra is installed
        from sentence_transformers import SentenceTransformer  # type: ignore

        class _STEmbedder:
            def __init__(self) -> None:
                self.model = SentenceTransformer("all-MiniLM-L6-v2")
                self.dim = self.model.get_sentence_embedding_dimension()

            def embed(self, text: str):
                return self.model.encode(text, normalize_embeddings=True).tolist()

            def embed_batch(self, texts):
                return self.model.encode(texts, normalize_embeddings=True).tolist()

        return _STEmbedder()  # type: ignore[return-value]
    except Exception:
        return HashingEmbedder()
