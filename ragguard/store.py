"""PostgreSQL / AlloyDB store using pgvector. Only documents with status
'active' are ever returned by search; quarantined content stays in the
database for review but is unreachable from retrieval."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Sequence

import psycopg
from psycopg.rows import dict_row

SCHEMA = Path(__file__).parent / "schema.sql"
STATUSES = ("active", "quarantined", "rejected")


def _vec(values: Sequence[float]) -> str:
    return "[" + ",".join(f"{v:.7g}" for v in values) + "]"


class PgVectorStore:
    def __init__(self, dsn: str, dim: int, schema_path: Path = SCHEMA):
        if not isinstance(dim, int) or not 1 <= dim <= 16000:
            raise ValueError("dim must be an integer between 1 and 16000")
        self.dsn, self.dim, self._schema_path = dsn, dim, schema_path

    def _conn(self):
        return psycopg.connect(self.dsn, row_factory=dict_row)

    def migrate(self) -> None:
        sql = self._schema_path.read_text().replace("{dim}", str(self.dim))
        with self._conn() as conn:
            conn.execute(sql)

    # --- writes ---
    def get_document(self, doc_id: str) -> Optional[dict]:
        with self._conn() as conn:
            return conn.execute("SELECT * FROM rg_documents WHERE id = %s", (doc_id,)).fetchone()

    def upsert_document(self, doc_id: str, source: str, sha256: str, status: str, risk: float,
                        findings: list, chunks: Sequence[str], embeddings: Sequence[Sequence[float]],
                        actor: str = "ingest") -> None:
        """Replace a document and its chunks in one transaction."""
        if status not in STATUSES:
            raise ValueError(f"bad status {status!r}")
        if len(chunks) != len(embeddings):
            raise ValueError("chunks and embeddings differ in length")
        if any(len(e) != self.dim for e in embeddings):
            raise ValueError(f"embedding dimension must be {self.dim}")
        with self._conn() as conn, conn.transaction():
            conn.execute("DELETE FROM rg_documents WHERE id = %s", (doc_id,))
            conn.execute(
                "INSERT INTO rg_documents (id, source, sha256, status, risk, findings) "
                "VALUES (%s, %s, %s, %s, %s, %s::jsonb)",
                (doc_id, source, sha256, status, risk, json.dumps(findings)))
            with conn.cursor() as cur:
                cur.executemany(
                    "INSERT INTO rg_chunks (document_id, ordinal, content, embedding) "
                    "VALUES (%s, %s, %s, %s::vector)",
                    [(doc_id, i, c, _vec(e)) for i, (c, e) in enumerate(zip(chunks, embeddings))])
            self._audit(conn, doc_id, f"ingested:{status}", actor, {"risk": risk, "chunks": len(chunks)})

    def review(self, doc_id: str, reviewer: str, release: bool) -> dict:
        """A human releases or rejects a quarantined document. Row lock prevents
        two reviewers deciding the same document."""
        if not reviewer.strip():
            raise ValueError("reviewer is required")
        with self._conn() as conn, conn.transaction():
            doc = conn.execute("SELECT * FROM rg_documents WHERE id = %s FOR UPDATE", (doc_id,)).fetchone()
            if doc is None:
                raise KeyError(doc_id)
            if doc["status"] != "quarantined":
                raise ValueError(f"document is {doc['status']}, not quarantined")
            status = "active" if release else "rejected"
            conn.execute(
                "UPDATE rg_documents SET status = %s, reviewed_by = %s, reviewed_at = now() WHERE id = %s",
                (status, reviewer, doc_id))
            if not release:
                conn.execute("DELETE FROM rg_chunks WHERE document_id = %s", (doc_id,))
            self._audit(conn, doc_id, "released" if release else "rejected", reviewer, {})
            return {**doc, "status": status, "reviewed_by": reviewer}

    @staticmethod
    def _audit(conn, doc_id: str, event: str, actor: str, detail: dict) -> None:
        conn.execute("INSERT INTO rg_audit (document_id, event, actor, detail) VALUES (%s, %s, %s, %s::jsonb)",
                     (doc_id, event, actor, json.dumps(detail)))

    # --- reads ---
    def search(self, query_embedding: Sequence[float], k: int = 5,
               sources: Optional[Sequence[str]] = None) -> list[dict]:
        if len(query_embedding) != self.dim:
            raise ValueError(f"embedding dimension must be {self.dim}")
        k = max(1, min(int(k), 50))
        vec = _vec(query_embedding)
        sql = ("SELECT d.id AS document_id, d.source, c.ordinal, c.content, "
               "1 - (c.embedding <=> %s::vector) AS score "
               "FROM rg_chunks c JOIN rg_documents d ON d.id = c.document_id "
               "WHERE d.status = 'active'")
        params: list = [vec]
        if sources is not None:
            sql += " AND d.source = ANY(%s)"
            params.append(list(sources))
        sql += " ORDER BY c.embedding <=> %s::vector LIMIT %s"
        params += [vec, k]
        with self._conn() as conn:
            return conn.execute(sql, params).fetchall()

    def list_documents(self, status: Optional[str] = None) -> list[dict]:
        with self._conn() as conn:
            if status:
                return conn.execute("SELECT * FROM rg_documents WHERE status = %s ORDER BY created_at, id",
                                    (status,)).fetchall()
            return conn.execute("SELECT * FROM rg_documents ORDER BY created_at, id").fetchall()

    def audit(self, doc_id: str) -> list[dict]:
        with self._conn() as conn:
            return conn.execute("SELECT event, actor, detail FROM rg_audit WHERE document_id = %s ORDER BY id",
                                (doc_id,)).fetchall()
