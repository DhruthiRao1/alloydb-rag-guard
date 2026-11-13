"""CLI.

  ragguard scan FILE...                       scan files, no database needed
  ragguard migrate                            create tables (needs RAGGUARD_DSN)
  ragguard ingest --source wiki FILE...       scan and index
  ragguard search "question"                  retrieve from active documents
  ragguard quarantine                         list quarantined documents
  ragguard review DOC_ID --reviewer NAME --release|--reject

Embeddings: set RAGGUARD_EMBEDDER=vertex with GOOGLE_CLOUD_PROJECT for Vertex AI;
the default is the offline hash embedder (demo quality only)."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .scanner import scan


def _pipeline():
    from .embeddings import HashEmbedder, VertexEmbedder
    from .pipeline import Pipeline
    from .store import PgVectorStore
    dsn = os.environ.get("RAGGUARD_DSN")
    if not dsn:
        sys.exit("Set RAGGUARD_DSN, e.g. postgresql://user:pass@127.0.0.1:5432/db")
    if os.environ.get("RAGGUARD_EMBEDDER") == "vertex":
        embedder = VertexEmbedder(os.environ["GOOGLE_CLOUD_PROJECT"],
                                  os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1"))
    else:
        embedder = HashEmbedder()
    return Pipeline(PgVectorStore(dsn, embedder.dim), embedder)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ragguard")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("files", nargs="+"); s.add_argument("--threshold", type=float, default=0.5)
    sub.add_parser("migrate")
    i = sub.add_parser("ingest"); i.add_argument("files", nargs="+"); i.add_argument("--source", required=True)
    q = sub.add_parser("search"); q.add_argument("query"); q.add_argument("-k", type=int, default=5)
    sub.add_parser("quarantine")
    r = sub.add_parser("review"); r.add_argument("doc_id"); r.add_argument("--reviewer", required=True)
    g = r.add_mutually_exclusive_group(required=True)
    g.add_argument("--release", action="store_true"); g.add_argument("--reject", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "scan":
        flagged = 0
        for name in a.files:
            result = scan(Path(name).read_text(errors="replace"))
            bad = result.risk >= a.threshold
            flagged += bad
            print(f"{'QUARANTINE' if bad else 'ok':10} risk={result.risk:<5} {name}  {', '.join(result.rules)}")
        return 1 if flagged else 0

    pipe = _pipeline()
    if a.cmd == "migrate":
        pipe.store.migrate(); print("schema ready")
    elif a.cmd == "ingest":
        for name in a.files:
            res = pipe.ingest(Path(name).name, a.source, Path(name).read_text(errors="replace"))
            print(f"{res.status:11} risk={res.risk:<5} {res.document_id}  {', '.join(res.rules)}")
    elif a.cmd == "search":
        for row in pipe.search(a.query, a.k):
            print(f"{row['score']:.3f}  {row['document_id']}#{row['ordinal']}  {row['content'][:100]!r}")
    elif a.cmd == "quarantine":
        for doc in pipe.store.list_documents("quarantined"):
            print(doc["id"], doc["risk"], json.dumps([f["rule"] for f in doc["findings"]]))
    elif a.cmd == "review":
        doc = pipe.store.review(a.doc_id, a.reviewer, release=a.release)
        print(f"{doc['id']} -> {doc['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
