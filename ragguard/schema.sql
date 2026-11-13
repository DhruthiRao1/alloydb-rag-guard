-- alloydb-rag-guard schema. Works on AlloyDB for PostgreSQL and on PostgreSQL 14+ with pgvector.
-- {dim} is replaced with the embedding dimension when the store applies it.
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS rg_documents (
    id           text PRIMARY KEY,
    source       text NOT NULL,
    sha256       text NOT NULL,
    status       text NOT NULL CHECK (status IN ('active', 'quarantined', 'rejected')),
    risk         real NOT NULL,
    findings     jsonb NOT NULL DEFAULT '[]',
    created_at   timestamptz NOT NULL DEFAULT now(),
    reviewed_by  text,
    reviewed_at  timestamptz
);

CREATE TABLE IF NOT EXISTS rg_chunks (
    id           bigserial PRIMARY KEY,
    document_id  text NOT NULL REFERENCES rg_documents(id) ON DELETE CASCADE,
    ordinal      int  NOT NULL,
    content      text NOT NULL,
    embedding    vector({dim}) NOT NULL,
    UNIQUE (document_id, ordinal)
);

CREATE INDEX IF NOT EXISTS rg_chunks_embedding_hnsw
    ON rg_chunks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS rg_documents_status ON rg_documents (status, source);

CREATE TABLE IF NOT EXISTS rg_audit (
    id           bigserial PRIMARY KEY,
    at           timestamptz NOT NULL DEFAULT now(),
    document_id  text NOT NULL,
    event        text NOT NULL,
    actor        text NOT NULL,
    detail       jsonb NOT NULL DEFAULT '{}'
);
