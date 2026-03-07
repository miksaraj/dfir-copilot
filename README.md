# DFIR Copilot — Forensics Assistant

A locally-run, evidence-led DFIR analysis orchestrator written in PHP 8.3+. The LLM never "does analysis" itself — it orchestrates deterministic tool runs, stores provenance, and produces hypotheses with explicit evidence pointers.

**Zero dependencies.** No Composer, no frameworks. Just PHP + curl + ssh2.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  HOST (Linux)                                                │
│                                                              │
│  ┌─────────┐   ┌──────────────┐   ┌───────────────────────┐ │
│  │  Ollama  │   │ dfirbus.php  │   │  Case Workspace       │ │
│  │ qwen3:8b │◄──┤  (CLI)       ├──►│  raw/ derived/ iocs/  │ │
│  │ worker + │   │              │   │  ledger.jsonl         │ │
│  │ judge    │   └──────┬───────┘   └───────────────────────┘ │
│  └─────────┘           │                                     │
│                        │                                     │
│  ┌──────────┐          │                                     │
│  │ nomic-   │          │                                     │
│  │ embed-   │◄─────────┤                                     │
│  │ text     │          │                                     │
│  │ (CPU)    │   ┌──────┴──────┐                              │
│  └──────────┘   │  RAG Index  │                              │
│                 │ knowledge/  │                               │
│            ┌────┤ index.json  ├────┐                         │
│            │    └─────────────┘    │                         │
│            ▼           ▼           ▼                         │
│     LocalExecutor  SSHExecutor  WinRMExecutor                │
│     (host tools)   (php-ssh2)  (curl + SOAP)                │
└──────────────────────────────────────────────────────────────┘
         │                │                │
         │           ┌────┴────┐     ┌─────┴─────┐
         │           │ REMnux  │     │ FLARE-VM  │
         │           │ strings │     │ PE tools  │
         │           │ yara    │     │ .NET      │
         │           │ capa    │     │ pestudio  │
         │           │ vol3    │     └───────────┘
         │           │ tshark  │
         │           │ plaso   │
         │           └─────────┘
```

## Model Selection

The default configuration uses **Qwen3:8b at Q4_K_M quantization** (~5.2 GB) as a single model serving both worker and judge roles via different system prompts. This is optimised for an **8 GB VRAM** GPU with 32 GB system RAM shared with VMs.

**Why Qwen3:8b?**
- **F1 0.92+ on tool calling** — the Docker Model Runner evaluation (June 2025) tested 21 models on 3,570 tool-calling cases. Qwen3:8b crushed Llama 3.1:8b (F1 0.79–0.83) and Qwen2.5:14b (F1 0.81).
- **Fits entirely in 8 GB VRAM** — full GPU inference at 40–50 tok/s. Models that spill to CPU drop to 5–12 tok/s (a 4–8× penalty).
- **Native function calling** — built into the chat template, not bolted on via prompt engineering.
- **Hybrid thinking mode** — chain-of-thought for complex analysis, fast non-thinking mode for simple tool dispatches.

**Why single-model dual-prompt instead of separate worker/judge models?**
Ollama can only load one model onto the GPU at a time. Swapping models incurs 5–15 seconds of loading overhead per switch. In a time-pressured CTF, cycling worker→judge→worker for every action step would bleed minutes. One model + two system prompts = zero swap overhead.

**Optional upgrades** (configure in `config.json`):
- `heavy_model`: `qwen3:14b` — for complex reasoning tasks like malware behaviour correlation. Runs at 8–12 tok/s with CPU/GPU split. Accepts a ~10s swap penalty.
- `specialist_model`: `Foundation-Sec-8B` (Cisco) — for dedicated threat intelligence and malware triage. Strong on CVE/ATT&CK knowledge but lacks native tool calling, so only useful for knowledge queries.

**Models to avoid:**
- DeepSeek-R1 distilled models — strong reasoning but no native tool calling, disqualifying them as agentic workers.
- MoE models (Qwen3:30b-a3b, Qwen3.5:35b-a3b) — despite few active parameters per token, all expert weights must be resident in memory (19–24 GB), exceeding the VRAM budget.

## Prerequisites

```bash
# PHP 8.3+ with required extensions
sudo apt install php8.3-cli php8.3-curl php8.3-ssh2 php8.3-mbstring

# Verify
php -v                    # Should show 8.3+
php -m | grep -E 'curl|ssh2|mbstring|json'

# Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the default model (single model serves both worker + judge)
ollama pull qwen3:8b

# Pull the embedding model for the knowledge base (runs on CPU, no VRAM needed)
ollama pull nomic-embed-text

# Optional: heavy model for complex reasoning (CPU/GPU split, slower)
# ollama pull qwen3:14b

# Optional: Cisco security specialist (import GGUF from HuggingFace)
# ollama create foundation-sec-8b -f Modelfile-foundation-sec

# Set recommended environment variables for 8 GB VRAM
export OLLAMA_KV_CACHE_TYPE=q8_0         # Halves KV cache — extends usable context to ~16K
export OLLAMA_NUM_PARALLEL=1             # Single request mode saves VRAM
export OLLAMA_MAX_LOADED_MODELS=1        # Keep only one model loaded at a time
```

## Setup Scripts

The `scripts/` directory contains two helper scripts that handle environment setup and verification. Run them in order: KVM setup first (once, well before the exercise), preflight check on exercise day.

### KVM/libvirt Setup — `scripts/setup-kvm.sh`

Run this **once** on Host Linux to set up the VM infrastructure. It's idempotent, so re-running it is safe.

```bash
sudo ./scripts/setup-kvm.sh
```

What it does:
- Installs `qemu-kvm`, `libvirt-daemon-system`, `virt-manager`, and related packages if missing
- Starts and enables `libvirtd`
- Adds your user to the `libvirt` and `kvm` groups (requires logout/login to take effect)
- Creates a `dfir-isolated` host-only network (bridge `virbr-dfir`, host IP `192.168.56.1`, DHCP range `.10`–`.50`)
- Verifies KVM hardware acceleration is available

After running, import your REMnux and FLARE-VM images via `virt-manager` and attach them to the `dfir-isolated` network. The bottom of the script has commented-out `virt-install` examples you can adapt for headless import.

**When to run:** Any time before the exercise — ideally the day you set up your Host Linux. Only needs to run once.

### Exercise-Day Preflight — `scripts/preflight.php`

Run this **on exercise day**, after VMs are booted and before the clock starts. It checks every dependency in one pass so you catch problems while you still have time to fix them.

```bash
php scripts/preflight.php
# or with a custom config path:
php scripts/preflight.php --config=/path/to/config.json
```

What it checks (in order):
1. **Config** — `config.json` exists and loads
2. **PHP** — version 8.3+, required extensions (`curl`, `mbstring`, `json`, `ssh2`)
3. **Ollama** — reachable, worker/judge models pulled, recommended env vars set
4. **RAG** — embedding model responds, knowledge base indexed with chunk counts
5. **REMnux** — SSH connects, key tools present (`strings`, `yara`, `capa`, `vol`, `tshark`, `log2timeline.py`), work directory writable, disk space
6. **FLARE-VM** — WinRM responds, shared folder exists (if configured)
7. **Workspace** — host disk space, YARA rules present

Output is colour-coded: green ✓ for pass, yellow ⚠ for warnings (non-blocking), red ✗ for failures (must-fix). Exits `0` if all critical checks pass, `1` if anything is broken.

**When to run:** Exercise morning, after `ollama serve` is running and VMs are booted. Run it again if you change config or restart a VM.

## Quick Start

The full workflow from fresh install to running analysis:

```bash
# ── One-time setup (days/weeks before exercise) ──────────────

# 1. Set up KVM (Host Linux only, run once)
sudo ./scripts/setup-kvm.sh

# 2. Import VMs via virt-manager, attach to dfir-isolated network

# 3. Generate config and edit it
php dfirbus.php init-config
# Edit config.json — set VM IPs, SSH key paths, model names

# 4. Pull models
ollama pull qwen3:8b
ollama pull nomic-embed-text

# ── Exercise day ─────────────────────────────────────────────

# 5. Boot VMs, start Ollama, then run preflight
ollama serve &
php scripts/preflight.php

# 6. Index scenario CTI into the knowledge base
#    (Place .md/.txt files in knowledge/actors/, knowledge/scenario/, knowledge/notes/)
php dfirbus.php kb-index

# 7. Create a case and ingest evidence
php dfirbus.php new-case challenge-01
php dfirbus.php ingest challenge-01 /path/to/challenge/bundle/

# ── Analysis ─────────────────────────────────────────────────

# 8. Run local triage (file IDs, entropy — no VMs needed)
php dfirbus.php triage challenge-01

# 9. Run specific adapters
php dfirbus.php run challenge-01 file_id file_path=raw/suspicious.exe
php dfirbus.php run challenge-01 strings_and_iocs file_path=raw/suspicious.exe
php dfirbus.php run challenge-01 yara_scan file_path=raw/suspicious.exe
php dfirbus.php run challenge-01 extract_iocs input_file=derived/suspicious_strings.txt
php dfirbus.php run challenge-01 attack_map 'observations=["powershell execution","scheduled task persistence","dns tunneling"]'

# 10. Run the agent (single worker + judge cycle)
php dfirbus.php agent challenge-01 "Triage the malware sample and identify C2 infrastructure"

# 11. Auto-pilot mode (repeats until judge approves)
php dfirbus.php agent-auto challenge-01 "Full analysis and attribution" --max-cycles=10

# 12. Generate blue-team report
php dfirbus.php report challenge-01
```

## Adapters

| Adapter | Target | Description |
|---------|--------|-------------|
| `intake_bundle` | local | Ingest + hash evidence |
| `file_id` | local | File type, hashes, entropy |
| `extract_iocs` | local | Parse IOCs from text files |
| `attack_map` | local | Map observations → ATT&CK |
| `actor_rank` | local | Rank actors from scenario CTI |
| `knowledge_search` | local | Search scenario CTI knowledge base (RAG) |
| `strings_and_iocs` | remnux | Extract strings via SSH (php-ssh2) |
| `yara_scan` | remnux | YARA rule scanning |
| `capa_scan` | remnux | Binary capability analysis |
| `vol3_triage` | remnux | Volatility 3 memory triage |
| `timeline_build` | remnux | Plaso super timeline |
| `pcap_summary` | remnux | PCAP network extraction (tshark) |
| `pe_quicklook` | flare | PE metadata via WinRM |

## Knowledge Base (RAG)

The knowledge base lets the agent search scenario CTI, threat actor profiles, and your team's notes during analysis and attribution. It uses local embeddings — no internet required during the exercise.

### How it works

1. You place `.md` or `.txt` files in `knowledge/`
2. `php dfirbus.php kb-index` chunks them (~512 chars, sentence-aware), embeds via `nomic-embed-text` (runs on CPU, doesn't touch VRAM), and writes a flat-file vector index
3. The agent has a `knowledge_search` tool that queries this index via cosine similarity
4. Results come back with **stable chunk IDs** like `TA-03:chunk_002` that the model must cite in its analysis

This is what makes attribution fast and consistent — the model cites "TA-03:chunk_002: Known to use schtasks for persistence" instead of paraphrasing from memory.

### Knowledge directory structure

```
knowledge/
├── actors/             ← One file per threat actor
│   ├── TA-01.md
│   ├── TA-02.md
│   └── TA-03.md
├── scenario/           ← Scenario briefs and CTI reports
│   ├── scenario_brief.md
│   └── threat_landscape.md
├── notes/              ← Your team's cheat sheets and prior-year notes
│   ├── common_ttps.md
│   └── last_year_lessons.md
├── README.md           ← Structure guide (not indexed)
└── index.json          ← Auto-generated vector index (gitignored)
```

Keep files focused — one actor per file, one topic per file. The chunker works best with coherent, single-topic documents.

### CLI commands

```bash
# Index everything in knowledge/ (re-indexes changed files)
php dfirbus.php kb-index

# Index a single file with a specific document ID
php dfirbus.php kb-ingest knowledge/actors/TA-03.md TA-03

# Search the knowledge base
php dfirbus.php kb-search "PowerShell persistence scheduled tasks"

# List indexed documents and chunk counts
php dfirbus.php kb-list

# Clear the entire index (files in knowledge/ are kept)
php dfirbus.php kb-clear
```

### How the agent uses it

The agent has access to `knowledge_search` as a tool, exactly like `yara_scan` or `file_id`. During the attribution phase, a typical flow looks like:

1. Agent observes TTPs from tool outputs (e.g., schtasks persistence, DNS tunneling)
2. Agent calls `knowledge_search(query="scheduled task persistence DNS tunneling")`
3. RAG returns ranked excerpts with chunk IDs and similarity scores
4. Agent cites specific chunks in its attribution: "Based on [TA-03:chunk_002], the use of schtasks with `/tn` names containing 'Update' matches TA-03's known TTPs"
5. Judge verifies that every attribution claim has a knowledge base citation

### Exercise day workflow

1. Receive scenario brief → save as `knowledge/scenario/scenario_brief.md`
2. Receive actor profiles → save each as `knowledge/actors/TA-XX.md`
3. Run `php dfirbus.php kb-index`
4. Verify: `php dfirbus.php kb-list` should show all documents
5. The agent can now search CTI during analysis and attribution

### Embedding model

The default embedding model is `nomic-embed-text` (137M params, 768 dimensions). It runs entirely on CPU via Ollama, so it doesn't compete with qwen3:8b for GPU VRAM. Embedding the entire knowledge base (~50–200 chunks) takes under 30 seconds.

### Technical details

The RAG implementation has no external dependencies — it's four PHP classes:

- **Chunker** — splits on sentence boundaries with configurable overlap (default: 512 chars, 64 overlap)
- **Embedder** — calls Ollama's `/api/embed` endpoint, supports batched embedding
- **VectorStore** — flat-file JSON index, brute-force cosine similarity search (adequate for <1000 chunks)
- **KnowledgeBase** — orchestrates ingest and search, strips markdown formatting before embedding

The vector index lives at `knowledge/index.json` and is gitignored — it's regenerated from source documents on each `kb-index` run.

## Project Structure

```
dfir-copilot/
├── dfirbus.php              ← Single CLI entry point
├── autoload.php             ← PSR-4 autoloader (no Composer)
├── config.json              ← Your config (generated by init-config)
├── .gitignore               ← Ignores cases/, keys/, config.json, index.json
├── scripts/
│   ├── setup-kvm.sh         ← KVM/libvirt setup (run once on Host Linux)
│   └── preflight.php        ← Exercise-day connectivity + dependency check
├── src/
│   ├── Config.php           ← Configuration loader
│   ├── Case/
│   │   └── Workspace.php    ← Case directory + provenance ledger
│   ├── Executors/
│   │   ├── ExecResult.php   ← Standardised execution result
│   │   ├── LocalExecutor.php← Host-side command execution
│   │   ├── SSHExecutor.php  ← REMnux via php-ssh2 + SFTP
│   │   └── WinRMExecutor.php← FLARE-VM via curl + WinRM SOAP
│   ├── Adapters/
│   │   ├── BaseAdapter.php  ← Base class + registry
│   │   ├── HostAdapters.php ← intake, file_id, iocs, attack_map, actor_rank
│   │   ├── REMnuxAdapters.php ← strings, yara, capa, vol3, plaso, pcap
│   │   ├── FLAREAdapters.php  ← pe_quicklook
│   │   └── RagAdapter.php  ← knowledge_search (queries the RAG index)
│   ├── Rag/
│   │   ├── Chunker.php     ← Sentence-aware text chunker
│   │   ├── Embedder.php    ← Ollama embedding API client
│   │   ├── VectorStore.php ← Flat-file vector index + cosine similarity
│   │   └── KnowledgeBase.php ← Ingest + search orchestrator
│   └── Agent/
│       ├── OllamaClient.php ← Ollama API via native curl
│       └── AgentLoop.php    ← Single-model dual-prompt worker + judge
├── knowledge/               ← Scenario CTI for RAG
│   ├── actors/              ← Threat actor profiles (one per file)
│   ├── scenario/            ← Scenario briefs
│   ├── notes/               ← Team notes and cheat sheets
│   └── index.json           ← Auto-generated vector index (gitignored)
├── cases/                   ← Case workspaces (gitignored)
├── keys/                    ← SSH keys (gitignored)
└── yara-rules/              ← Your curated YARA rulesets
```

## VM Setup

### REMnux (SSH via php-ssh2)
```bash
# On REMnux:
sudo systemctl enable ssh && sudo systemctl start ssh
mkdir -p /tmp/dfirbus

# On your host — generate and install SSH key:
ssh-keygen -t ed25519 -f keys/remnux_ed25519 -N ""
ssh-copy-id -i keys/remnux_ed25519.pub remnux@192.168.56.10

# Verify from host:
php -r "
  \$c = ssh2_connect('192.168.56.10', 22);
  ssh2_auth_pubkey_file(\$c, 'remnux', 'keys/remnux_ed25519.pub', 'keys/remnux_ed25519');
  \$s = ssh2_exec(\$c, 'echo ok');
  stream_set_blocking(\$s, true);
  echo stream_get_contents(\$s);
"
```

### FLARE-VM (WinRM via curl)
```powershell
# On FLARE-VM (run as Administrator):
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
mkdir C:\dfirbus
# Restrict WinRM to host-only network adapter only
```

### KVM/libvirt Setup (Host Linux)

Handled by the setup script — see [Setup Scripts](#setup-scripts) above.

```bash
sudo ./scripts/setup-kvm.sh
```

## Configuration (config.json)

Generated by `php dfirbus.php init-config`. Key settings:

```json
{
  "remnux": {
    "host": "192.168.56.10",
    "user": "remnux",
    "key_file": "keys/remnux_ed25519",
    "port": 22
  },
  "flare": {
    "host": "192.168.56.11",
    "user": "flare",
    "password": "flare",
    "shared_host_path": "/home/you/shared-flare",
    "shared_vm_path": "Z:\\"
  },
  "ollama": {
    "worker_model": "qwen3:8b",
    "judge_model": "qwen3:8b",
    "kv_cache_type": "q8_0",
    "context_length": 8192,
    "worker_thinking": true,
    "judge_thinking": false,
    "heavy_model": "",
    "specialist_model": ""
  },
  "rag": {
    "knowledge_dir": "knowledge",
    "embedding_model": "nomic-embed-text",
    "chunk_size": 512,
    "chunk_overlap": 64,
    "top_k": 5
  }
}
```

### VRAM Budget Guide

| Configuration | VRAM usage | Throughput | When to use |
|---|---|---|---|
| `qwen3:8b` + 8K ctx + q8_0 KV | ~6.2 GB | 40–50 tok/s | **Default — fast interactive CTF** |
| `qwen3:8b` + 16K ctx + q8_0 KV | ~7.5 GB | 35–45 tok/s | Large artifacts (disk image strings) |
| `qwen3:14b` (CPU/GPU split) | ~10.7 GB total | 8–12 tok/s | Complex multi-step reasoning |

Note: `nomic-embed-text` runs on CPU and does not consume VRAM. It adds no overhead to the LLM inference budget.

## How the Agent Works

1. **Worker** (qwen3:8b, thinking mode) gets the current case state — files, IOCs, tools already run, hypotheses
2. Worker decides which adapter to call next via Ollama native tool calling
3. Adapter executes on the correct target (local/REMnux/FLARE) — the model never runs arbitrary commands
4. For attribution, the worker calls `knowledge_search` to retrieve scenario CTI excerpts with citable chunk IDs
5. Results go back to the worker, who extracts findings and calls more tools or proposes conclusions
6. **Judge** (same model, non-thinking mode, different system prompt) reviews: rejects claims without evidence pointers, demands alternative hypotheses, flags missing triage steps
7. If rejected → required actions feed back to the worker → loop continues

Since both roles share a model, there is **zero model-swap overhead** between cycles.

## Safety

- The LLM **never** runs arbitrary shell commands — only whitelisted adapters
- Every tool run is logged with full provenance (command, inputs, outputs, hashes, timing)
- All samples treated as hostile: no auto-execution, no read-write mounting
- Keep the system offline during the exercise unless rules explicitly allow otherwise
- The provenance ledger (`ledger.jsonl`) doubles as your after-action notes

## Extending

To add a new adapter:

1. Create a class extending `BaseAdapter` in the appropriate file
2. Define `NAME`, `VERSION`, `DESCRIPTION`, `TARGET` constants
3. Implement `getToolSchema()` (Ollama function-calling format)
4. Implement `execute()` — use the appropriate executor
5. Register it in `dfirbus.php`'s `registerAllAdapters()`

The agent will automatically see the new tool in its next cycle.
