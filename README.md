# DFIR Copilot — Forensics CTF Assistant

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

### VM Images

Before running the setup script, download and place these files in `/var/lib/libvirt/images/`:

| Image | Filename | Source |
|-------|----------|--------|
| REMnux OVA | `remnux-noble-amd64.ova` | [remnux.org](https://remnux.org/#702) |
| Windows 10 ISO | `Win10_22H2_ENInt_x64v1.iso` | [microsoft.com](https://www.microsoft.com/software-download/windows10ISO) |

The setup script expects these exact paths. REMnux Noble ships as a VMware OVA with a gzip-compressed VMDK inside — the script handles the OVA→QCOW2 conversion automatically.

## Setup Scripts

The `scripts/` directory contains two helper scripts that handle environment setup and verification. Run them in order: KVM setup first (once, well before the exercise), preflight check on exercise day.

### KVM/libvirt Setup — `scripts/setup-kvm.sh`

Run this **once** on Host Linux to set up the VM infrastructure. It's idempotent, so re-running it is safe.

```bash
sudo ./scripts/setup-kvm.sh
```

What it does:
1. Installs `qemu-kvm`, `qemu-utils`, `libvirt-daemon-system`, `virt-manager`, and related packages if missing
2. Starts and enables `libvirtd`
3. Adds your user to the `libvirt` and `kvm` groups (**requires logout/login to take effect**)
4. Creates a `dfir-isolated` host-only network (bridge `virbr-dfir`, host IP `192.168.56.1`, DHCP `.10`–`.50`)
5. Verifies KVM hardware acceleration is available
6. **REMnux:** extracts the VMDK from the OVA, decompresses it (the Noble OVA ships with a `.vmdk.gz`), converts to QCOW2 via `qemu-img`, and registers the VM via `virt-install --import`
7. **FLARE-VM:** creates a blank 100 GB QCOW2 target disk and registers a VM that boots from the Windows ISO via VNC

After running, **log out and back in** (for group membership to take effect), then set the libvirt connection URI permanently:

```bash
# Add to your ~/.bashrc or ~/.zshrc
export LIBVIRT_DEFAULT_URI="qemu:///system"
```

Without this, `virsh` defaults to `qemu:///session` (a separate, empty user-space instance) and you won't see your VMs.

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

# 1. Place VM images in /var/lib/libvirt/images/ (see Prerequisites > VM Images)

# 2. Set up KVM, convert OVA, register VMs (run once)
sudo ./scripts/setup-kvm.sh
# Log out and back in, then: export LIBVIRT_DEFAULT_URI="qemu:///system"

# 3. Configure REMnux post-boot (see VM Setup > REMnux below)

# 4. Generate config and edit it
php dfirbus.php init-config
# Edit config.json — set VM IPs, SSH key paths, model names

# 5. Pull models
ollama pull qwen3:8b
ollama pull nomic-embed-text

# ── Exercise day ─────────────────────────────────────────────

# 6. Boot VMs, start Ollama, then run preflight
ollama serve &
php scripts/preflight.php

# 7. Index scenario CTI into the knowledge base
#    (Place .md/.txt files in knowledge/actors/, knowledge/scenario/, knowledge/notes/)
php dfirbus.php kb-index

# 8. Create a case and ingest evidence
php dfirbus.php new-case challenge-01
php dfirbus.php ingest challenge-01 /path/to/challenge/bundle/

# If the bundle contained a zip you extracted manually after ingesting, re-hash:
php dfirbus.php reinventory challenge-01

# ── Analysis ─────────────────────────────────────────────────

# 9. Run local triage (file IDs, entropy — no VMs needed)
php dfirbus.php triage challenge-01

# 10. Run specific adapters
php dfirbus.php run challenge-01 file_id file_path=raw/suspicious.exe
php dfirbus.php run challenge-01 strings_and_iocs file_path=raw/suspicious.exe
php dfirbus.php run challenge-01 yara_scan file_path=raw/suspicious.exe
php dfirbus.php run challenge-01 extract_iocs input_file=derived/suspicious_strings.txt
php dfirbus.php run challenge-01 attack_map 'observations=["powershell execution","scheduled task persistence","dns tunneling"]'

# 11. Run the agent (single worker + judge cycle)
php dfirbus.php agent challenge-01 "Triage the malware sample and identify C2 infrastructure"

# 12. Auto-pilot mode (repeats until judge approves)
php dfirbus.php agent-auto challenge-01 "Full analysis and attribution" --max-cycles=10

# 13. Generate blue-team report
php dfirbus.php report challenge-01
```

## Case Evidence Commands

| Command | Description |
|---------|-------------|
| `new-case <id>` | Create the case directory structure |
| `ingest <id> <path>` | Copy a file or directory into `raw/`, hash everything, write `inventory.json` |
| `reinventory <id>` | Re-hash all files already in `raw/` and rewrite `inventory.json` |
| `list-files <id>` | Show all files in `raw/` with sizes |
| `status <id>` | Print the current case state (IOCs, hypotheses, TTPs) |
| `ledger <id>` | Show the provenance ledger (tool runs, timestamps, exit codes) |
| `triage <id>` | Run `file_id` locally on every file in `raw/` |
| `report <id>` | Generate a blue-team Markdown report |

### When to use `reinventory`

`ingest` hashes files **at copy time**. If you later extract a zip directly inside `raw/` (e.g. `unzip evidence.zip -d cases/challenge-01/raw/evidence/`), the new files won't appear in `inventory.json`. Running `reinventory` fixes this:

```bash
# Unzip into raw/ yourself
unzip evidence.zip -d cases/challenge-01/raw/evidence/

# Then rebuild inventory.json in-place (no file copies, just re-hashing)
php dfirbus.php reinventory challenge-01
```

Safe to run at any time — only `inventory.json` is modified, no evidence files are touched.

## Adapters

### Core / Local

| Adapter | Target | Description |
|---------|--------|-------------|
| `intake_bundle` | local | Ingest + hash evidence |
| `file_id` | local | File type, hashes, entropy |
| `extract_iocs` | local | Parse IOCs from text files |
| `log_parse` | local | Parse log files (syslog, JSON lines, CSV) with keyword/regex filter |
| `list_directory` | local | Browse evidence directory tree |
| `decrypt_zip` | local | Extract plain or password-protected ZIPs; supports recursive ZIP-in-ZIP (e.g. GitHub Actions log bundles) |
| `attack_map` | local | Map observations → ATT&CK |
| `actor_rank` | local | Rank actors from scenario CTI |
| `knowledge_search` | local | Search scenario CTI knowledge base (RAG) |
| `inject_pdf_read` | local | Extract text and questions from inject PDFs (challenge briefings) |

### Cloud & Log Forensics

| Adapter | Target | Description |
|---------|--------|-------------|
| `gzipped_log_parse` | local | Parse gzip-compressed log files (`.gz`, `.log.gz`) transparently — Nexus request/audit logs, rotated syslogs |
| `cloudtrail_query` | local | Query AWS CloudTrail gzip-JSON logs across regions and dates; filter by source IP, access key, event name, service, error code |
| `gh_security_log` | local | Parse GitHub Security Audit Log JSON — epoch-ms timestamps, action/actor/IP filters, auto-flags high-risk events (MFA bypass, unrecognized login, OAuth token creation) |
| `s3_access_log_query` | local | Query a directory of S3 / ObjectVault server access log files in bulk; filter by source IP, HTTP method, object key prefix, operation type, or status code — eliminates per-file `log_parse` overhead |

### REMnux (SSH)

| Adapter | Target | Description |
|---------|--------|-------------|
| `strings_and_iocs` | remnux | Extract strings via SSH |
| `yara_scan` | remnux | YARA rule scanning |
| `capa_scan` | remnux | Binary capability analysis |
| `vol3_triage` | remnux | Volatility 3 triage — Windows and Linux profiles |
| `timeline_build` | remnux | Plaso super timeline |
| `pcap_summary` | remnux | PCAP network extraction (tshark); optional TLS decryption via keylog |
| `pcap_filter` | remnux | Targeted tshark filter + field extraction |
| `pcap_carve` | remnux | TCP stream carving and file recovery from PCAPs |
| `oletools_analyze` | remnux | Office document macro and VBA analysis |
| `evtx_parse` | remnux | Parse Windows Event Log (.evtx) files with event ID filtering |

### Disk Image Forensics (TSK / REMnux)

| Adapter | Target | Description |
|---------|--------|-------------|
| `disk_timeline` | remnux | MAC-time filesystem timeline using `fls + mactime` (no log2timeline required) |
| `mft_search` | remnux | Find files by name pattern in MFT |
| `registry_parse` | remnux | Extract Windows registry hives via `icat + regripper` |
| `prefetch_parse` | remnux | Parse Windows Prefetch execution history |

### FLARE-VM (WinRM)

| Adapter | Target | Description |
|---------|--------|-------------|
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

The setup script (`scripts/setup-kvm.sh`) handles VM registration, but each VM requires post-boot configuration. Do this **once**, well before the exercise.

### REMnux Post-Boot Configuration

The REMnux OVA is a vanilla Ubuntu 24.04 base — `remnux install` is what transforms it into the full DFIR toolkit. The OVA was built for VMware, so KVM NIC names won't match and networking needs manual configuration.

#### 1. Start the VM and open its console

```bash
virsh start remnux
virt-manager   # double-click 'remnux' to open the console
```

Default credentials: `remnux` / `malware`

#### 2. Configure networking for KVM

The OVA ships with VMware NIC names (`ens32` etc.) which don't exist under KVM. Create a netplan config for the actual interface names:

```bash
# Inside REMnux console — find your NIC names
ip link show
# You'll see something like enp1s0, enp7s0 (not ens32)
```

Match MAC addresses to networks: on the **host**, run `virsh domiflist remnux` to see which MAC is on `dfir-isolated`. Inside **REMnux**, `ip link show` lists each NIC's MAC.

Create the netplan config (both NICs on DHCP initially — we'll set static later):

```bash
sudo tee /etc/netplan/01-kvm-network.yaml << 'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    enp1s0:       # adjust to your dfir-isolated NIC name
      dhcp4: true
EOF

sudo chmod 600 /etc/netplan/01-kvm-network.yaml
sudo systemctl enable systemd-networkd --now
sudo netplan apply
```

> **Note:** If NetworkManager shows devices as "strictly unmanaged", that's expected — use `renderer: networkd` in netplan to bypass it.

#### 3. Add temporary internet access for `remnux install`

The `dfir-isolated` network is host-only (no NAT, no internet). You need a temporary second NIC on the `default` libvirt network to download packages.

On the **host**:

```bash
# Ensure the default NAT network is running
virsh net-start default 2>/dev/null || true

# Attach a temporary internet NIC
virsh attach-interface remnux network default --model virtio --config --live
```

Inside **REMnux**, add the new NIC to netplan temporarily:

```bash
# Find the new NIC name (ip link show — the one that just appeared)
sudo tee /etc/netplan/01-kvm-network.yaml << 'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    enp1s0:       # dfir-isolated NIC
      dhcp4: true
    enp7s0:       # temporary internet NIC — adjust name
      dhcp4: true
EOF

sudo netplan apply
curl -I https://remnux.org   # verify internet access
```

#### 4. Run `remnux install`

```bash
sudo remnux install
```

> ⏳ This takes **20–60 minutes** — it installs Volatility, YARA, Capa, Plaso, tshark, and hundreds of other tools.

#### 5. Configure SSH

```bash
# Inside REMnux:
sudo apt install -y openssh-server   # if not already installed by remnux install
echo "UseDNS no" | sudo tee -a /etc/ssh/sshd_config   # prevent DNS lookup timeout on isolated network
sudo systemctl enable ssh --now
mkdir -p /tmp/dfirbus
```

#### 6. Set static IP and remove internet NIC

Update netplan to a static IP and remove the temporary internet NIC entry:

```bash
sudo tee /etc/netplan/01-kvm-network.yaml << 'EOF'
network:
  version: 2
  renderer: networkd
  ethernets:
    enp1s0:       # dfir-isolated NIC — adjust name
      addresses: [192.168.56.10/24]
EOF

sudo netplan apply
```

On the **host**, detach the temporary internet NIC:

```bash
virsh domiflist remnux   # note the MAC of the 'default' NIC
virsh detach-interface remnux network --mac <MAC-of-default-NIC> --config --live
```

#### 7. Set up SSH keys (on the host)

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
mkdir -p keys
ssh-keygen -t ed25519 -f keys/remnux_ed25519 -N ""
ssh-copy-id -i keys/remnux_ed25519.pub remnux@192.168.56.10

# Verify passwordless login:
ssh -i keys/remnux_ed25519 remnux@192.168.56.10 echo ok

# Verify via php-ssh2:
php -r "
  \$c = ssh2_connect('192.168.56.10', 22);
  ssh2_auth_pubkey_file(\$c, 'remnux', 'keys/remnux_ed25519.pub', 'keys/remnux_ed25519');
  \$s = ssh2_exec(\$c, 'echo ok');
  stream_set_blocking(\$s, true);
  echo stream_get_contents(\$s);
"
```

#### 8. Set up shared folder for large files (optional but recommended)

Without this, the agent copies evidence files to REMnux over SFTP for every analysis run. For small binaries this is fine, but memory dumps are often 4–16 GB — SFTP at ~40 MB/s takes minutes. A 9p virtio filesystem passthrough eliminates the transfer entirely.

On the **host**, write the device XML and attach it to the VM:

```bash
# Create the cases directory if it doesn't exist yet
mkdir -p /<path-to-cases>

# Grant QEMU (runs as libvirt-qemu) traversal access to every directory in the path.
# Replace CASES_DIR with the absolute path to your cases folder (from config.json cases_root).
CASES_DIR="/absolute/path/to/your/cases"

# Walk each component of the path, granting traversal only:
path="$CASES_DIR"
while [ "$path" != "/" ]; do
    sudo setfacl -m u:libvirt-qemu:x "$path"
    path=$(dirname "$path")
done
# Grant read/write/execute on the cases directory itself:
sudo setfacl -m u:libvirt-qemu:rwx "$CASES_DIR"

# Write the device XML and attach it persistently
cat > /tmp/remnux-share.xml << EOF
<filesystem type='mount' accessmode='mapped'>
  <driver type='path'/>
  <source dir='${CASES_DIR}'/>
  <target dir='dfir-cases'/>
</filesystem>
EOF

sudo virsh attach-device remnux --config /tmp/remnux-share.xml
rm /tmp/remnux-share.xml
```

Restart REMnux for the device to appear:

```bash
sudo virsh shutdown remnux
sudo virsh start remnux
```

Inside **REMnux**, mount and make it persistent:

```bash
sudo mkdir -p /mnt/cases
sudo mount -t 9p -o trans=virtio dfir-cases /mnt/cases

# Persist across reboots
echo 'dfir-cases /mnt/cases 9p trans=virtio,_netdev 0 0' | sudo tee -a /etc/fstab

# Verify — case directories created on the host appear here immediately
ls /mnt/cases
```

Then update `config.json`:

```json
"remnux": {
    ...
    "shared_host_path": "<same absolute path as CASES_DIR above>",
    "shared_vm_path": "/mnt/cases"
}
```

With this configured, when the agent runs `vol3_triage` on a 4 GB memory dump, REMnux accesses it at `/mnt/cases/<case-id>/raw/<dump>.mem` directly — zero transfer time.

### FLARE-VM Post-Boot Configuration

The setup script boots the VM from the Windows ISO. Complete the setup in order:

#### 1. Install Windows 10

Open `virt-manager`, connect to the `flare-vm` display, and click through the Windows 10 setup wizard.

#### 2. Add temporary internet access for FLARE-VM installation

The `dfir-isolated` network is host-only (no NAT, no internet). The FLARE-VM installer needs internet to download packages, so attach a temporary second NIC on the `default` libvirt network.

On the **host**:

```bash
# Ensure the default NAT network is running
virsh net-start default 2>/dev/null || true

# Attach a temporary internet NIC — use e1000e, NOT virtio
# (Windows has inbox e1000e drivers; virtio requires a separate driver package)
sudo virsh attach-interface flare-vm \
  --type network \
  --source default \
  --model e1000e \
  --config --live
```

Inside **Windows**, the new adapter should appear in Network Connections (`ncpa.cpl`) and automatically receive a DHCP address in the `192.168.122.0/24` range. Verify with:

```cmd
ping 8.8.8.8
```

> If the adapter doesn't appear, open **Device Manager → Action → Scan for hardware changes**.

#### 3. Install FLARE-VM toolkit

Follow the official installation guide at [github.com/mandiant/flare-vm](https://github.com/mandiant/flare-vm). This installs PE analysis tools, .NET decompilers, debuggers, and other DFIR utilities.

> ⏳ This takes **30–60+ minutes** depending on which packages you select.

Once installation is complete, **remove the internet NIC** on the host:

```bash
sudo virsh domiflist flare-vm   # find the MAC of the 'default' NIC
sudo virsh detach-interface flare-vm \
  --type network \
  --mac <MAC-of-default-NIC> \
  --config --live
```

#### 4. Configure WinRM for DFIR Copilot

After FLARE-VM installation is complete, open PowerShell **as Administrator**:

```powershell
# Bootstrap WinRM service, listener, and firewall rule
winrm quickconfig -Force

# Enable remoting — -SkipNetworkProfileCheck is required because the dfir-isolated NIC
# has no gateway, so Windows classifies it as "Public" and blocks remoting by default
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Enable Basic auth and unencrypted HTTP (required by the PHP WinRM executor)
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true

# Create the work directory
mkdir C:\dfirbus
```

Set a static IP of `192.168.56.11` on the network adapter connected to `dfir-isolated`
(Control Panel → Network Connections → right-click adapter → Properties → TCP/IPv4):
- IP address: `192.168.56.11`
- Subnet mask: `255.255.255.0`
- Default gateway: *(leave blank)*
- DNS: *(leave blank)*

> **Note:** If ping from the host fails, allow ICMP in Windows Firewall:
> ```powershell
> netsh advfirewall firewall add rule name="Allow ICMPv4" protocol=icmpv4:8,any dir=in action=allow
> ```

#### 5. Configure the shared folder (optional)

The shared folder lets the agent transfer PE samples to FLARE-VM automatically. Skip this if you plan to copy files manually.

On the **host**, install Samba and create a share:

```bash
sudo apt install -y samba
mkdir -p ~/shared-flare

# Add to the end of /etc/samba/smb.conf:
sudo tee -a /etc/samba/smb.conf << 'EOF'

[dfirbus]
   path = /home/<your-username>/shared-flare
   browseable = yes
   read only = no
   guest ok = yes
   force user = <your-username>
EOF

sudo systemctl restart smbd nmbd

# Allow SMB only from the isolated subnet
sudo ufw allow from 192.168.56.0/24 to any port 445
sudo ufw allow from 192.168.56.0/24 to any port 139
```

Verify the share is visible (host IP on the isolated bridge is `192.168.56.1`):

```bash
smbclient -L //192.168.56.1 -N   # should list 'dfirbus'
```

Inside **Windows**, map it as a persistent `Z:` drive:

```powershell
net use Z: \\192.168.56.1\dfirbus /persistent:yes
dir Z:\   # verify
```

Then update `config.json`:

```json
"shared_host_path": "/home/<your-username>/shared-flare",
"shared_vm_path": "Z:\\"
```

## Configuration (config.json)

Generated by `php dfirbus.php init-config`. Key settings:

```json
{
  "remnux": {
    "host": "192.168.56.10",
    "user": "remnux",
    "key_file": "keys/remnux_ed25519",
    "port": 22,
    "shared_host_path": "",
    "shared_vm_path": ""
  },
  "flare": {
    "host": "192.168.56.11",
    "user": "flare",
    "password": "flare",
    "shared_host_path": "/home/<your-username>/shared-flare",
    "shared_vm_path": "Z:\\"
  },
  "ollama": {
    "worker_model": "qwen3:8b",
    "judge_model": "qwen3:8b",
    "temperature": 0.1,
    "timeout": 600,
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

> **`ollama.timeout`** — seconds to wait for a single Ollama response. The default is 300 s. With `worker_thinking: true`, qwen3:8b can spend 2–3 minutes on a complex reasoning step before producing output, and the conversation history grows longer each cycle. 120 s (the previous default) is reliably too short for multi-cycle `agent-auto` runs. If you are using `qwen3:14b` with CPU/GPU split (8–12 tok/s), consider raising this to 600 s.

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
