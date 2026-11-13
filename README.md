# alloydb-rag-guard

Stops poisoned documents from reaching a RAG system. Every document is scanned before it is indexed; anything suspicious is quarantined in the database, invisible to retrieval, until a human releases or rejects it. The vector store is AlloyDB for PostgreSQL (or any PostgreSQL with pgvector), with embeddings from Vertex AI.

## The problem

A RAG assistant trusts what it retrieves. If someone can get a document into the index, such as a wiki edit, an uploaded PDF or a scraped web page, they can plant text aimed at the model: "ignore previous instructions", hidden white-on-white text, an invisible Unicode payload, or a markdown image that leaks the conversation to their server. This is indirect prompt injection, and filtering the user's prompt does nothing about it.

## How it works

```
document --> scan (raw + normalised text) --> risk score
                                                 |
                      risk < 0.5                 |            risk >= 0.5
                 +-------------------------------+------------------------------+
                 v                                                              v
   chunk -> embed (Vertex AI) -> AlloyDB                    stored as 'quarantined' with findings
   status = 'active'                                        reviewer: release -> active | reject -> chunks deleted

search(query) --> embed --> pgvector cosine search WHERE status = 'active' [AND source = ANY(allowed)]
```

What the scanner detects:

| Technique | Rule |
|---|---|
| Instruction override ("ignore previous instructions") | `instruction_override` |
| Text addressed to the model, answer steering | `addressed_to_model`, `conditional_answer_steering` |
| Fake system or assistant messages | `fake_system_message` |
| Requests for the system prompt, keys or credentials | `prompt_extraction` |
| Leaks through image URLs or "send the conversation to" | `data_exfiltration` |
| HTML comments and CSS-hidden text aimed at the model | `hidden_html_comment`, `hidden_styled_text` |
| Zero-width characters splitting keywords | `zero_width_characters` (then rules run on normalised text) |
| Invisible Unicode tag characters | `unicode_tag_smuggling` |
| Base64-wrapped payloads | `base64:<rule>` |

Design points:

- **The whole document is scanned before chunking**, so an attack can't hide across a chunk boundary.
- **Hidden text is never indexed.** Comments, CSS-hidden spans and invisible characters are stripped from what gets embedded, even if a reviewer later releases the document.
- **Quarantine is enforced in SQL.** Search always filters on `status = 'active'`; there is no code path that returns quarantined chunks.
- **Re-ingesting unchanged content keeps the human's decision.** Changed content is re-scanned from scratch.
- **Writes are transactional** and reviews take a row lock, so two reviewers can't both decide one document.
- **Every ingest and review is written to an audit table.**

## Quick start

```bash
pip install .                       # add ".[vertex]" for Vertex AI embeddings
docker compose up -d                # local PostgreSQL + pgvector
export RAGGUARD_DSN=postgresql://postgres:ragguard@127.0.0.1:5432/ragguard

ragguard scan docs/*.md             # scan only, no database needed
ragguard migrate
ragguard ingest --source wiki docs/*.md
ragguard search "what is the return policy"
ragguard quarantine
ragguard review suspicious.md --reviewer you@example.com --reject
```

```python
from ragguard.embeddings import VertexEmbedder
from ragguard.pipeline import Pipeline
from ragguard.store import PgVectorStore

embedder = VertexEmbedder(project="my-project", location="us-central1")   # gemini-embedding-001, 768 dims
pipe = Pipeline(PgVectorStore(dsn, embedder.dim), embedder)
pipe.store.migrate()
result = pipe.ingest("handbook.md", source="hr-wiki", text=open("handbook.md").read())
hits = pipe.search("leave policy", k=5, sources=["hr-wiki"])
```

### Using AlloyDB

AlloyDB is PostgreSQL-compatible and supports the `vector` extension, so the schema in `ragguard/schema.sql` applies as is. Create a cluster and primary instance, run the AlloyDB Auth Proxy locally (or connect over private IP from Cloud Run or GKE), and point `RAGGUARD_DSN` at it. AlloyDB also offers its own ScaNN-based vector index as an alternative to HNSW; see the AlloyDB documentation if you want to try it at larger scale. AlloyDB bills while the cluster is running, so delete test clusters when you're done.

## Tests

```bash
pip install . pytest
RAGGUARD_TEST_DSN=postgresql://postgres:ragguard@127.0.0.1:5432/ragguard pytest -q    # 40 tests
```

29 tests cover the scanner and chunker offline. 11 are integration tests against a real PostgreSQL with pgvector: quarantined content never appears in search, release and reject, re-ingestion, source filtering, SQL injection in ids and sources, rollback on a failed write, and six concurrent reviewers with exactly one winning. CI runs them against a `pgvector/pgvector` service container.

## Detection results

On the hand-written set in `tests/corpus.py`: 12 of 12 poisoned documents quarantined, 0 of 13 benign documents flagged. The benign set was chosen to be awkward (engineering docs full of "must" and "always", HTML with comments and styles, base64 assets, Kannada text with joiners, a product spec that talks about "the assistant").

Read that number for what it is: a small set written alongside the rules, so it shows the rules do what they were designed to do, not how they perform on attacks they haven't seen. Rules like these are cheap and catch the common techniques; a paraphrased or translated attack can get past them.

## Status and limits

- Tested on PostgreSQL 16 with pgvector 0.6 and Python 3.13. The schema uses only standard pgvector features, but it has not been run on an AlloyDB cluster, and the Vertex AI embedder has not been exercised against the live API. Run both in your own project before relying on them.
- English-centric patterns. Attacks in other languages need more rules or a classifier.
- Documents that legitimately discuss prompt injection (security training, this README) will be quarantined. That is what the review step is for.
- Text only. PDFs, Office files and images need extraction first, and hidden text in those formats needs format-aware checks.
- Planned: an optional LLM judge for borderline scores, embedding-outlier detection per source, and row-level security for per-tenant isolation.

Related: [guardrails-gateway](https://github.com/DhruthiRao1/guardrails-gateway) screens prompts and responses; this project screens the knowledge base.

## License

MIT
