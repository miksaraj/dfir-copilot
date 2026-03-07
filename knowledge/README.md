# Knowledge Base

Place scenario CTI documents here for RAG indexing.

## Expected structure

```
knowledge/
├── README.md           ← This file (not indexed)
├── actors/             ← Threat actor profiles
│   ├── TA-01.md
│   ├── TA-02.md
│   └── TA-03.md
├── scenario/           ← Scenario briefs and CTI reports
│   ├── scenario_brief.md
│   └── threat_landscape.md
├── notes/              ← Your team's cheat sheets and prior-year notes
│   ├── common_ttps.md
│   └── last_year_lessons.md
└── index.json          ← Auto-generated vector index (gitignored)
```

## File format

Plain text (`.txt`) or Markdown (`.md`). Keep files focused — one actor per file,
one topic per file. The chunker splits on sentence boundaries at ~512 characters.

## Indexing

```bash
# Index everything in knowledge/
php dfirbus.php kb-index

# Index a single file
php dfirbus.php kb-ingest knowledge/actors/TA-03.md TA-03

# Search
php dfirbus.php kb-search "PowerShell persistence scheduled tasks"

# List indexed documents
php dfirbus.php kb-list
```

## How the agent uses it

The agent has a `knowledge_search` tool that queries this index.
Results come back with stable chunk IDs like `TA-03:chunk_002`
that the model cites in its analysis.

## Exercise day workflow

1. Receive scenario brief → save as `knowledge/scenario/scenario_brief.md`
2. Receive actor profiles → save each as `knowledge/actors/TA-XX.md`
3. Run `php dfirbus.php kb-index`
4. The agent can now search CTI during analysis and attribution