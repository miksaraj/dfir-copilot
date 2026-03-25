# Changelog

All notable changes to DFIR Copilot are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows a modified SemVer scheme: `<year>-<major>.<minor>.<patch>`.

---

## [2026-0.2.1] — 2026-03-25

### Fixed

- **`agent-auto` loop premature exit** (`src/Agent/AgentLoop.php`) — the auto-pilot loop previously stopped on the first cycle where `approved: true`, even when the judge simultaneously listed outstanding `required_actions`. The judge evaluates honesty of what has been done so far, not overall completeness, so an early approval with pending actions means "this is clean — keep going", not "we're finished". The termination condition is now `approved === true` **and** `required_actions` is empty. When approved-but-incomplete, the required actions are fed forward as the next instruction (with a distinct prefix so the worker knows it is building on solid ground rather than correcting errors). Console output distinguishes three states: genuinely complete, approved-but-continuing, and rejected.

---

## [2026-0.2.0] — 2026-03-25

### Added

- **`reinventory` command** (`dfirbus.php`, `src/Case/Workspace.php`) — rebuilds `inventory.json` from the files that are already present in `raw/`, without copying or moving anything. Useful when evidence zips are extracted in-place after the initial `ingest` run. Re-hashes every file under `raw/` recursively, sorts entries by path for deterministic output, and updates the `ingested_at` timestamp. Only `inventory.json` is modified; no evidence files are touched.
- **Case Evidence Commands section** (`README.md`) — new reference table covering all case-management CLI commands, plus a dedicated "When to use `reinventory`" subsection with the concrete `unzip` → `reinventory` workflow.

---

## [2026-0.1.0] — 2026-03-22

Initial public release. End-to-end DFIR analysis orchestration from a single PHP CLI entry point — no Composer, no frameworks.

### Added

#### Core Infrastructure
- **`dfirbus.php`** — single CLI entry point with commands: `init-config`, `new-case`, `ingest`, `triage`, `run`, `agent`, `agent-auto`, `report`, `kb-index`, `kb-ingest`, `kb-search`, `kb-list`, `kb-clear`
- **`autoload.php`** — PSR-4 class autoloader with no Composer dependency
- **`config.json`** — generated configuration file covering REMnux SSH, FLARE-VM WinRM, Ollama model selection, and RAG settings
- **`src/Config.php`** — configuration loader
- **`src/Case/Workspace.php`** — case directory management and append-only JSONL provenance ledger

#### Executors
- **`src/Executors/LocalExecutor.php`** — host-side command execution via `proc_open`
- **`src/Executors/SSHExecutor.php`** — REMnux remote execution via `php-ssh2`; includes SFTP upload/download and optional 9p virtio shared-path routing to bypass SFTP for large files
- **`src/Executors/WinRMExecutor.php`** — FLARE-VM remote execution via raw WinRM SOAP over HTTP; includes UUID-based `MessageID` headers for request correlation
- **`src/Executors/ExecResult.php`** — standardised execution result value object

#### Adapters
- **`src/Adapters/BaseAdapter.php`** — abstract base class defining the adapter contract; includes a central `AdapterRegistry` replacing per-command `match` blocks in the entry point
- **`src/Adapters/HostAdapters.php`** — local adapters:
  - `intake_bundle` — evidence ingestion with SHA-256 hashing
  - `file_id` — file type identification (magic bytes), hashes, and entropy
  - `extract_iocs` — IOC extraction from text (IPs, domains, URLs, registry keys, hashes)
  - `attack_map` — maps free-text observations to MITRE ATT&CK techniques via Ollama; regex delimiter/escaping hardened against special-character technique descriptions
  - `actor_rank` — ranks threat actors from scenario CTI by relevance to observed TTPs
  - `log_parse` — local log file analysis supporting syslog, JSON-lines, and CSV formats with keyword/regex filtering
- **`src/Adapters/REMnuxAdapters.php`** — SSH-backed adapters:
  - `strings_and_iocs` — remote string extraction and IOC parsing via REMnux
  - `yara_scan` — YARA rule scanning
  - `capa_scan` — binary capability analysis via Capa
  - `vol3_triage` — Volatility 3 triage (Windows and Linux memory profiles)
  - `timeline_build` — Plaso super-timeline construction
  - `pcap_summary` — PCAP network extraction via tshark; optional TLS decryption via keylog file
  - `inject_pdf_read` — PDF text and structured question extraction from challenge briefings
  - `evtx_parse` — Windows Event Log (`.evtx`) parsing with event ID filtering
  - All REMnux adapters updated with `SharedPath` support: when `shared_vm_path` and `shared_host_path` are configured, large evidence files are accessed via the 9p mount directly, eliminating SFTP transfer overhead
- **`src/Adapters/FLAREAdapters.php`** — WinRM-backed adapters:
  - `pe_quicklook` — PE metadata extraction (headers, imports, exports, sections) via WinRM
- **`src/Adapters/RagAdapter.php`** — `knowledge_search` adapter; queries the RAG vector index and returns ranked excerpts with stable chunk IDs for model citation

#### RAG Knowledge Base
- **`src/Rag/Chunker.php`** — sentence-aware text chunker (default 512-char chunks, 64-char overlap)
- **`src/Rag/Embedder.php`** — Ollama `/api/embed` client with batched embedding support
- **`src/Rag/VectorStore.php`** — flat-file JSON vector index with brute-force cosine similarity search
- **`src/Rag/KnowledgeBase.php`** — ingest and search orchestrator; strips Markdown formatting before embedding; assigns stable chunk IDs (e.g. `TA-03:chunk_002`) for provenance

#### Agent
- **`src/Agent/OllamaClient.php`** — Ollama API client via native `curl`; supports native function/tool calling in Ollama's chat format
- **`src/Agent/AgentLoop.php`** — single-model dual-prompt worker + judge loop:
  - Worker (thinking mode) dispatches tool calls via Ollama native function calling
  - Judge (non-thinking mode, separate system prompt) reviews outputs, rejects unsupported claims, demands evidence citations
  - Zero model-swap overhead — both roles share one loaded model
  - Improved agent system prompts for more precise tool dispatch and evidence-led reasoning

#### Scripts
- **`scripts/setup-kvm.sh`** — idempotent KVM/libvirt setup script: installs packages, creates `dfir-isolated` host-only network, converts REMnux OVA (including gzip-compressed VMDK extraction) to QCOW2, registers both VMs via `virt-install`
- **`scripts/preflight.php`** — exercise-day preflight checker: validates PHP version and extensions, Ollama reachability and model availability, REMnux SSH and tool presence, FLARE-VM WinRM, RAG index, and workspace disk space; colour-coded output, exits non-zero on critical failures

#### Documentation
- **`README.md`** — full project documentation: architecture diagram, model selection rationale (Qwen3:8b benchmarks, VRAM budget, single-model dual-prompt design), prerequisites, setup scripts, quick start, adapter reference, RAG usage, VM setup guides for REMnux and FLARE-VM (including temporary internet NIC procedures and shared folder configuration), configuration reference, agent internals, safety notes, and extension guide
- **`LICENSE`** — GNU General Public License v3

---

[2026-0.2.1]: https://github.com/miksaraj/dfir-copilot/releases/tag/2026-0.2.1
[2026-0.2.0]: https://github.com/miksaraj/dfir-copilot/releases/tag/2026-0.2.0
[2026-0.1.0]: https://github.com/miksaraj/dfir-copilot/releases/tag/2026-0.1.0
