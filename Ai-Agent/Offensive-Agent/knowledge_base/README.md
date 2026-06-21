# knowledge_base

Markdown knowledge base for the Offensive agent's retrieval-augmented generation (RAG) layer.

## What this is

A curated set of Markdown notes — vulnerability exploitation playbooks, security-tool usage references, and target-specific notes for the DVWA lab. On the first scan the Offensive agent ingests every `*.md` file under this folder into a FAISS vector index (plus a BM25 sparse index), and the ReAct exploit agents query it at runtime to ground their reasoning in concrete payloads, commands, and detection signals rather than relying on model memory alone.

This folder is **data**, not code. The ingestion and retrieval logic lives in `../utils/rag.py` (`RAGEngine`), wired into the agent via `../api.py`. See the [Offensive agent README](../README.md) and the [root README](../../../README.md) for how scans run.

## How it is used

- **Auto-ingest on first scan.** `api.py` calls `RAGEngine.ingest()` the first time a scan starts (guarded by an `_ingested` flag). Files are read recursively (`rglob("*.md")`), split with a Markdown-aware `RecursiveCharacterTextSplitter` (chunk size 1500, overlap 200, split on `##`/`###`/`####` headings), embedded with OpenAI embeddings, and saved to a local FAISS index at `faiss_index/` (sibling of the configured `chroma_db` path). A BM25 retriever is built over the same chunks.
- **Hybrid retrieval at query time.** `RAGEngine.query()` fuses dense (FAISS, weight 0.6) and sparse (BM25, weight 0.4) results with reciprocal-rank fusion, then boosts chunks whose metadata matches the requested `vuln_type` or `tool_name`. Exploit agents pull this context while planning and exploiting.
- **YAML front-matter drives metadata.** A leading `--- ... ---` block is parsed for `vuln_type`, `tool_name`, `severity`, and `category`, which feed the metadata boosts during retrieval. Files without front-matter still ingest; `category` defaults to the parent folder name and `filename`/`source` are always recorded.

Because ingestion only runs when no FAISS index exists yet (or is explicitly re-triggered), editing or adding files takes effect after the index is rebuilt — delete the persisted `faiss_index/` directory to force a fresh ingest.

## Layout

| Path | Contents |
|------|----------|
| `vulnerabilities/` | Per-class exploitation notes (SQLi, XSS, SSRF, SSTI, XXE, LFI, OAuth, CORS, deserialization, request smuggling, race conditions, broken access control, auth bypass, file upload, security misconfiguration). Most carry YAML front-matter (`vuln_type`, `severity`, `cwe`, `owasp`, `related_tools`, `exploit_agent`, `tags`). Includes a contributor `README.md`. |
| `tools/` | Usage references for security tools the agents drive — e.g. `sqlmap`, `nuclei`, `ffuf`, `nmap`, `nikto`, `hydra`, `commix`, `dalfox`, `xsser`, `arjun`, `katana`, `gau`, `gobuster`, `httpx`, `subfinder`, `whatweb`, `wpscan`, `jsluice`, `interactsh`, `curl`. Front-matter typically sets `tool_name`, `category`, `tags`, `used_by_agents`. |
| `dvwa/` | Target-specific notes for the DVWA lab, one file per vulnerability and security level (`low`/`medium`/`high`) — brute force, command injection, CSRF, file inclusion, file upload, SQLi, reflected/stored XSS. Includes URLs, vulnerable parameters, source-code behavior, and detection/exploitation steps. |

## Adding content

- Drop a new `.md` file into the most appropriate subfolder.
- Add a YAML front-matter block when possible so retrieval can match on `vuln_type` / `tool_name`:
  ```yaml
  ---
  vuln_type: sqli
  severity: critical
  related_tools: [sqlmap, curl]
  exploit_agent: sqli_agent
  tags: [union, blind, error-based]
  ---
  ```
- Structure the body with `##`/`###` headings — they are the primary chunk boundaries, so keep each section self-contained.
- Re-ingest (remove the persisted `faiss_index/` or run a fresh scan) to pick up the change.
