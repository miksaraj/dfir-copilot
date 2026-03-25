#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/autoload.php';

use DFIRCopilot\Config;
use DFIRCopilot\Case\Workspace;
use DFIRCopilot\Adapters\AdapterRegistry;
use DFIRCopilot\Adapters\{IntakeBundle, FileID, ExtractIOCs, ATTACKMap, ActorRank};
use DFIRCopilot\Adapters\{StringsAndIOCs, YARAScan, CapaScan, Vol3Triage, TimelineBuild, PCAPSummary};
use DFIRCopilot\Adapters\PEQuicklook;
use DFIRCopilot\Adapters\KnowledgeSearch;
use DFIRCopilot\Agent\{OllamaClient, AgentLoop};
use DFIRCopilot\Executors\SSHExecutor;
use DFIRCopilot\Executors\WinRMExecutor;
use DFIRCopilot\Rag\KnowledgeBase;
use DFIRCopilot\Adapters\{InjectPdfRead, EvtxParse, LogParse, ListDirectory, DecryptZip};
use DFIRCopilot\Adapters\{DiskTimeline, MftSearch, RegistryParse, PrefetchParse};
use DFIRCopilot\Adapters\{PcapFilter, PcapCarve, OletoolsAnalyze};

// ── Adapter registration ─────────────────────────────────────────

function registerAllAdapters(): void
{
	AdapterRegistry::register(new IntakeBundle());
	AdapterRegistry::register(new FileID());
	AdapterRegistry::register(new ExtractIOCs());
	AdapterRegistry::register(new ATTACKMap());
	AdapterRegistry::register(new ActorRank());
	AdapterRegistry::register(new StringsAndIOCs());
	AdapterRegistry::register(new YARAScan());
	AdapterRegistry::register(new CapaScan());
	AdapterRegistry::register(new Vol3Triage());
	AdapterRegistry::register(new TimelineBuild());
	AdapterRegistry::register(new PCAPSummary());
	AdapterRegistry::register(new PEQuicklook());
	AdapterRegistry::register(new KnowledgeSearch());
	AdapterRegistry::register(new InjectPdfRead());
	AdapterRegistry::register(new EvtxParse());
	AdapterRegistry::register(new LogParse());
	AdapterRegistry::register(new ListDirectory());
	AdapterRegistry::register(new DecryptZip());
	// Tier 1 — disk image forensics (TSK-based, no log2timeline required)
	AdapterRegistry::register(new DiskTimeline());
	AdapterRegistry::register(new MftSearch());
	AdapterRegistry::register(new RegistryParse());
	AdapterRegistry::register(new PrefetchParse());
	// Tier 2 — PCAP deep-dive + Office document analysis
	AdapterRegistry::register(new PcapFilter());
	AdapterRegistry::register(new PcapCarve());
	AdapterRegistry::register(new OletoolsAnalyze());
}

// ── CLI helpers ──────────────────────────────────────────────────

function out(string $msg): void { echo $msg . "\n"; }
function err(string $msg): void { fwrite(STDERR, $msg . "\n"); }

function getConfigPath(array $argv): string
{
	for ($i = 0; $i < count($argv); $i++) {
		if (str_starts_with($argv[$i], '--config=')) {
			return substr($argv[$i], 9);
		}
		if ($argv[$i] === '--config' && isset($argv[$i + 1])) {
			return $argv[$i + 1];
		}
	}
	return 'config.json';
}

function usage(): never
{
	out(<<<'USAGE'
DFIR Copilot — Forensics CTF Assistant

Usage: php dfirbus.php <command> [options]

Commands:
  init-config                       Generate default config.json
  new-case <case_id>                Create a new case workspace
  ingest <case_id> <path>           Ingest evidence bundle
  reinventory <case_id>             Rebuild inventory.json from files already in raw/
  run <case_id> <adapter> [args]    Run a specific adapter (args: key=value)
  list-adapters                     List all available adapters
  list-files <case_id>              List raw files in a case
  status <case_id>                  Show case state
  ledger <case_id>                  Show provenance ledger
  test-connections                  Test VM, Ollama, and RAG connectivity
  triage <case_id>                  Run local triage on all files
  agent <case_id> [instruction]     Run one worker+judge cycle
  agent-auto <case_id> [instruction] [--max-cycles=N]  Auto-pilot
  report <case_id>                  Generate blue-team report

Knowledge base:
  kb-index                          Index all files in knowledge/
  kb-ingest <file> <doc_id>         Index a single file with a given ID
  kb-search <query>                 Search the knowledge base
  kb-list                           List indexed documents
  kb-clear                          Clear the knowledge base index

Global options:
  --config=<path>                   Config file (default: config.json)
USAGE);
	exit(1);
}

// ── Commands ─────────────────────────────────────────────────────

function cmdInitConfig(): void
{
	Config::generateDefault('config.json');
	out("Generated config.json");
	out("Edit this file to set your VM IPs, SSH keys, model preferences.");
	out("");
	out("Default model: qwen3:8b (single model for both worker + judge)");
	out("Pull it:  ollama pull qwen3:8b");
	out("");
	out("RAG knowledge base:");
	out("  Pull embedding model:  ollama pull nomic-embed-text");
	out("  Place scenario CTI in: knowledge/");
	out("  Index:                 php dfirbus.php kb-index");
	out("");
	out("Recommended Ollama env vars for 8 GB VRAM:");
	out("  export OLLAMA_KV_CACHE_TYPE=q8_0");
	out("  export OLLAMA_NUM_PARALLEL=1");
	out("  export OLLAMA_MAX_LOADED_MODELS=1");
}

function cmdNewCase(Config $cfg, string $caseId): void
{
	$case = new Workspace($cfg->casesRoot, $caseId);
	$case->create();
	out("Created case workspace: {$case->caseDir}");
	out("  raw/       — place evidence here (or use 'ingest')");
	out("  derived/   — tool outputs");
	out("  iocs/      — extracted IOCs");
	out("  notes/     — your notes + actor profiles");
	out("  timelines/ — generated timelines");
}

function cmdIngest(Config $cfg, string $caseId, string $path): void
{
	$case = new Workspace($cfg->casesRoot, $caseId);
	if (!is_dir($case->caseDir)) $case->create();

	$inventory = $case->ingestBundle($path);
	$count     = count($inventory['files']);
	out("Ingested {$count} files into {$case->rawDir}");

	foreach (array_slice($inventory['files'], 0, 20) as $f) {
		$name = $f['relative_path'] ?? $f['stored_as'] ?? '?';
		out("  {$name} ({$f['size_bytes']} bytes)");
	}
	if ($count > 20) out("  ... and " . ($count - 20) . " more");
}

function cmdReinventory(Config $cfg, string $caseId): void
{
	$case      = new Workspace($cfg->casesRoot, $caseId);
	$inventory = $case->rebuildInventory();
	$count     = count($inventory['files']);
	out("Rebuilt inventory for case '{$caseId}': {$count} file(s) hashed.");
	foreach (array_slice($inventory['files'], 0, 20) as $f) {
		out(sprintf("  %-52s %10d B  %s", $f['relative_path'], $f['size_bytes'], substr($f['sha256'], 0, 16) . '...'));
	}
	if ($count > 20) out("  ... and " . ($count - 20) . " more");
	out("Saved to: {$case->inventoryPath}");
}

function cmdRun(Config $cfg, string $caseId, string $adapterName, array $rawArgs): void
{
	registerAllAdapters();
	$case    = new Workspace($cfg->casesRoot, $caseId);
	$adapter = AdapterRegistry::get($adapterName);

	if ($adapter === null) {
		$available = array_column(AdapterRegistry::list(), 'name');
		err("Unknown adapter: {$adapterName}");
		err("Available: " . implode(', ', $available));
		exit(1);
	}

	$params = [];
	foreach ($rawArgs as $arg) {
		if (str_contains($arg, '=')) {
			[$k, $v] = explode('=', $arg, 2);
			$decoded = json_decode($v, true);
			$params[$k] = $decoded !== null ? $decoded : $v;
		}
	}

	$target = $adapter::TARGET;
	out("Running {$adapterName} on {$target}...");
	$result = $adapter->run($case, $cfg, $params);

	out("\nSuccess: " . ($result->success ? 'yes' : 'no'));
	if ($result->error !== '') out("Error: {$result->error}");
	out("Produced files: " . implode(', ', $result->producedFiles));
	out("\nStructured results:");
	out(mb_substr(json_encode($result->structuredResults, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), 0, 3000));

	if (!empty($result->evidencePointers)) {
		out("\nEvidence pointers:");
		foreach (array_slice($result->evidencePointers, 0, 15) as $ep) {
			out("  {$ep}");
		}
	}
}

function cmdListAdapters(): void
{
	registerAllAdapters();
	$adapters = AdapterRegistry::list();
	out("Available adapters (" . count($adapters) . "):\n");
	foreach ($adapters as $a) {
		out(sprintf("  %-25s [%-7s]  %s", $a['name'], $a['target'], mb_substr($a['description'], 0, 60)));
	}
}

function cmdListFiles(Config $cfg, string $caseId): void
{
	$case  = new Workspace($cfg->casesRoot, $caseId);
	$files = $case->listRawFiles();
	out("Raw files in {$caseId} (" . count($files) . "):");
	foreach ($files as $f) {
		out(sprintf("  %-50s %10.1f KB", $f['path'], $f['size_bytes'] / 1024));
	}
}

function cmdStatus(Config $cfg, string $caseId): void
{
	$case = new Workspace($cfg->casesRoot, $caseId);
	out(json_encode($case->getState(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function cmdLedger(Config $cfg, string $caseId): void
{
	$case    = new Workspace($cfg->casesRoot, $caseId);
	$entries = $case->getLedger();
	out("Provenance ledger (" . count($entries) . " entries):\n");
	foreach ($entries as $e) {
		$status = $e['exit_code'] === 0 ? '✓' : '✗';
		out(sprintf("  %s %s  %-25s  %ss",
					$status,
					substr($e['timestamp'], 0, 19),
					$e['tool_name'],
					$e['duration_seconds'] ?? '?',
			));
		if (!empty($e['stderr_excerpt'])) {
			out("    stderr: " . mb_substr($e['stderr_excerpt'], 0, 100));
		}
	}
}

function cmdTestConnections(Config $cfg): void
{
	out("Testing connections...\n");

	// Ollama
	$client = OllamaClient::fromConfig($cfg);
	$status = $client->testConnection();
	if ($status['connected']) {
		out("✓ Ollama: connected");
		out("  Models: " . implode(', ', array_slice($status['models'], 0, 10)));

		$workerOk = in_array($cfg->ollamaWorkerModel, $status['models'], true)
			|| count(array_filter($status['models'], fn($m) => str_contains($m, $cfg->ollamaWorkerModel))) > 0;
		out("  Worker ({$cfg->ollamaWorkerModel}): " . ($workerOk ? '✓' : '✗ NOT FOUND — run: ollama pull ' . $cfg->ollamaWorkerModel));

		if ($cfg->isSingleModelMode()) {
			out("  Judge: same model (single-model dual-prompt mode) ✓");
		} else {
			$judgeOk = in_array($cfg->ollamaJudgeModel, $status['models'], true)
				|| count(array_filter($status['models'], fn($m) => str_contains($m, $cfg->ollamaJudgeModel))) > 0;
			out("  Judge ({$cfg->ollamaJudgeModel}): " . ($judgeOk ? '✓' : '✗ NOT FOUND'));
		}

		if ($cfg->hasHeavyModel()) {
			$heavyOk = in_array($cfg->ollamaHeavyModel, $status['models'], true)
				|| count(array_filter($status['models'], fn($m) => str_contains($m, $cfg->ollamaHeavyModel))) > 0;
			out("  Heavy ({$cfg->ollamaHeavyModel}): " . ($heavyOk ? '✓' : '✗ NOT FOUND (optional)'));
		}

		$envVars = $client->getRecommendedEnvVars();
		out("\n  Recommended Ollama env vars:");
		foreach ($envVars as $k => $v) {
			$current = getenv($k) ?: '(not set)';
			$match   = $current === $v ? '✓' : "✗ current={$current}";
			out("    {$k}={$v}  {$match}");
		}
	} else {
		out("✗ Ollama: " . ($status['error'] ?? 'not connected'));
	}

	// RAG embedding model
	try {
		$kb = KnowledgeBase::fromConfig($cfg);
		$ragStatus = $kb->testConnection();
		if ($ragStatus['connected']) {
			out("\n✓ RAG embedding ({$cfg->ragEmbeddingModel}): connected ({$ragStatus['dimensions']}d vectors)");
			out("  Indexed chunks: {$kb->chunkCount()}");
			$docs = $kb->listDocuments();
			foreach ($docs as $d) {
				out("    {$d['doc_id']}: {$d['chunks']} chunks");
			}
		} else {
			out("\n✗ RAG embedding ({$cfg->ragEmbeddingModel}): " . ($ragStatus['error'] ?? 'not connected'));
			out("  Run: ollama pull {$cfg->ragEmbeddingModel}");
		}
	} catch (\Throwable $e) {
		out("\n✗ RAG: " . $e->getMessage());
	}

	// REMnux SSH
	try {
		$ssh = SSHExecutor::fromConfig($cfg);
		if ($ssh->testConnection()) {
			out("\n✓ REMnux SSH: connected ({$cfg->remnuxHost})");
			foreach (['strings', 'yara', 'capa', 'vol', 'tshark', 'log2timeline.py'] as $tool) {
				$r = $ssh->run("which {$tool} 2>/dev/null || echo 'NOT FOUND'");
				$found = !str_contains($r->stdout, 'NOT FOUND');
				out("  " . ($found ? '✓' : '✗') . " {$tool}: " . mb_substr(trim($r->stdout), 0, 80));
			}
		} else {
			out("\n✗ REMnux SSH: cannot connect to {$cfg->remnuxHost}");
		}
	} catch (\Throwable $e) {
		out("\n✗ REMnux SSH: " . $e->getMessage());
	}

	// FLARE-VM WinRM
	try {
		$winrm = WinRMExecutor::fromConfig($cfg);
		if ($winrm->testConnection()) {
			out("\n✓ FLARE-VM WinRM: connected ({$cfg->flareHost})");
		} else {
			out("\n✗ FLARE-VM WinRM: cannot connect to {$cfg->flareHost}");
		}
	} catch (\Throwable $e) {
		out("\n✗ FLARE-VM WinRM: " . $e->getMessage());
	}
}

function cmdTriage(Config $cfg, string $caseId): void
{
	registerAllAdapters();
	$case  = new Workspace($cfg->casesRoot, $caseId);
	$files = $case->listRawFiles();

	if (empty($files)) {
		out("No files in raw/. Ingest evidence first.");
		return;
	}

	out("Running local triage on " . count($files) . " files...\n");

	$fileId = AdapterRegistry::get('file_id');

	foreach ($files as $f) {
		out("\n--- {$f['name']} ({$f['size_bytes']} bytes) ---");

		$result = $fileId->run($case, $cfg, ['file_path' => $f['path']]);
		$r      = $result->structuredResults;
		out("  Type:    " . ($r['magic'] ?? 'unknown'));
		out("  SHA256:  " . mb_substr($r['sha256'] ?? '?', 0, 16) . "...");
		out("  Entropy: " . ($r['entropy'] ?? '?'));

		if ($r['is_pe'] ?? false)  out("  → PE binary detected. Run: strings_and_iocs, yara_scan, pe_quicklook");
		if ($r['is_elf'] ?? false) out("  → ELF binary detected. Run: strings_and_iocs, yara_scan, capa_scan");
	}

	out("\n\nLocal triage complete.");
	out("Remote adapters (REMnux/FLARE) need VM connectivity.");
	out("Run 'test-connections' to verify, then run individual adapters.");
}

function cmdAgent(Config $cfg, string $caseId, string $instruction): void
{
	registerAllAdapters();
	$case  = new Workspace($cfg->casesRoot, $caseId);
	$agent = new AgentLoop($cfg, $case);

	$result = $agent->runFullCycle($instruction);

	out("\n" . str_repeat('=', 60));
	out("WORKER ANALYSIS:");
	out(str_repeat('=', 60));
	out($result['worker_analysis']);
	out("\n" . str_repeat('=', 60));
	out("JUDGE VERDICT:");
	out(str_repeat('=', 60));
	out(json_encode($result['judge_verdict'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function cmdAgentAuto(Config $cfg, string $caseId, string $instruction, int $maxCycles): void
{
	registerAllAdapters();
	$case  = new Workspace($cfg->casesRoot, $caseId);
	$agent = new AgentLoop($cfg, $case);

	$results = $agent->runAuto($instruction, $maxCycles);

	out("\nCompleted " . count($results) . " cycles.");

	$reportPath = "{$case->notesDir}/agent_run.json";

	// Load existing runs (or start fresh)
	$allRuns = [];
	if (file_exists($reportPath) && filesize($reportPath) > 0) {
		$decoded = json_decode(file_get_contents($reportPath), true);
		// Handle both the old format (bare array of cycles) and the new format
		// (array of run objects). If the first element has a 'run_id' key it's
		// already in the new format; otherwise wrap the old data as a legacy run.
		if (is_array($decoded) && !empty($decoded)) {
			if (isset($decoded[0]['run_id'])) {
				$allRuns = $decoded;  // new format — keep as-is
			} else {
				$allRuns = [[  // wrap old bare cycles array as a legacy run
					'run_id'      => 1,
					'timestamp'   => null,
					'instruction' => '(legacy — instruction not recorded)',
					'cycles'      => $decoded,
				]];
			}
		}
	}

	$allRuns[] = [
		'run_id'      => count($allRuns) + 1,
		'timestamp'   => date('c'),
		'instruction' => $instruction,
		'cycles'      => $results,
	];

	file_put_contents($reportPath, json_encode($allRuns, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
	out("Full results saved to: {$reportPath} (run #" . count($allRuns) . ")");
}

function cmdReport(Config $cfg, string $caseId): void
{
	$case   = new Workspace($cfg->casesRoot, $caseId);
	$state  = $case->getState();
	$ledger = $case->getLedger();

	$lines = [
		"# DFIR Report: {$caseId}",
		"Generated from " . count($ledger) . " tool runs\n",
		"## Summary",
		"(Fill in after analysis)\n",
		"## IOCs",
	];

	foreach ($state['iocs'] ?? [] as $ioc) {
		$lines[] = sprintf("- **%s**: `%s` (confidence: %s, source: %s)",
						   $ioc['type'], $ioc['value'], $ioc['confidence'] ?? '?', $ioc['source_tool'] ?? '?');
	}

	$lines[] = "\n## TTPs (ATT&CK)";
	foreach ($state['ttps'] ?? [] as $ttp) { $lines[] = "- {$ttp}"; }

	$lines[] = "\n## Attribution Candidates";
	$actorFile = "{$case->derivedDir}/actor_rankings.json";
	if (file_exists($actorFile)) {
		$rankings = json_decode(file_get_contents($actorFile), true) ?: [];
		foreach ($rankings as $r) {
			$lines[] = sprintf("- **%s**: match=%d, conflicts=%d, confidence=%s",
							   $r['actor'], $r['match_score'], $r['conflict_score'], $r['confidence']);
		}
	}

	$lines[] = "\n## Hypotheses";
	foreach ($state['hypotheses'] ?? [] as $h) {
		$lines[] = "- [{$h['status']}] {$h['statement']}";
		foreach ($h['supporting_evidence'] ?? [] as $s) { $lines[] = "  - Supporting: {$s}"; }
	}

	$lines[] = "\n## Recommended Containment Pivots";
	$lines[] = "(Fill in: domains, IPs, scheduled tasks, registry keys, etc.)\n";
	$lines[] = "## Evidence Ledger (last 10 tool runs)";
	foreach (array_slice($ledger, -10) as $e) {
		$status  = $e['exit_code'] === 0 ? '✓' : '✗';
		$lines[] = "- {$status} {$e['tool_name']} at " . substr($e['timestamp'], 0, 19);
	}

	$report     = implode("\n", $lines);
	$reportPath = "{$case->notesDir}/blue_team_report.md";
	file_put_contents($reportPath, $report);
	out($report);
	out("\nSaved to: {$reportPath}");
}

// ── Knowledge base commands ──────────────────────────────────────

function cmdKbIndex(Config $cfg): void
{
	$kb  = KnowledgeBase::fromConfig($cfg);
	$dir = $cfg->ragKnowledgeDir;

	if (!is_dir($dir)) {
		out("Knowledge directory not found: {$dir}");
		out("Create it and add scenario CTI files (.md, .txt).");
		return;
	}

	out("Indexing all files in {$dir}...\n");
	$results = $kb->ingestDirectory($dir);

	if (empty($results)) {
		out("No indexable files found (.txt, .md) in {$dir}");
		return;
	}

	$totalChunks = 0;
	foreach ($results as $docId => $chunks) {
		out(sprintf("  %-30s %d chunks", $docId, $chunks));
		$totalChunks += $chunks;
	}
	out("\nIndexed {$totalChunks} chunks from " . count($results) . " documents.");
	out("The agent can now use knowledge_search to query scenario CTI.");
}

function cmdKbIngest(Config $cfg, string $filePath, string $docId): void
{
	$kb = KnowledgeBase::fromConfig($cfg);
	out("Indexing {$filePath} as '{$docId}'...");
	$chunks = $kb->ingestFile($filePath, $docId);
	out("Indexed {$chunks} chunks.");
}

function cmdKbSearch(Config $cfg, string $query): void
{
	$kb = KnowledgeBase::fromConfig($cfg);

	if ($kb->chunkCount() === 0) {
		out("Knowledge base is empty. Run: php dfirbus.php kb-index");
		return;
	}

	out("Searching: \"{$query}\"\n");
	$results = $kb->search($query, $cfg->ragTopK);

	if (empty($results)) {
		out("No results found.");
		return;
	}

	foreach ($results as $r) {
		$score = round($r['score'], 3);
		$type  = $r['metadata']['type'] ?? '?';
		out("[{$r['id']}] score={$score} type={$type}");
		out("  " . mb_substr($r['text'], 0, 200));
		out("");
	}
}

function cmdKbList(Config $cfg): void
{
	$kb   = KnowledgeBase::fromConfig($cfg);
	$docs = $kb->listDocuments();

	if (empty($docs)) {
		out("Knowledge base is empty.");
		return;
	}

	out("Indexed documents (" . count($docs) . "):\n");
	foreach ($docs as $d) {
		out(sprintf("  %-30s %d chunks", $d['doc_id'], $d['chunks']));
	}
	out("\nTotal chunks: " . $kb->chunkCount());
}

function cmdKbClear(Config $cfg): void
{
	$kb = KnowledgeBase::fromConfig($cfg);
	$kb->clear();
	out("Knowledge base cleared.");
}

// ── Main ─────────────────────────────────────────────────────────

$configPath = getConfigPath($argv);

$cleanArgv = [];
$skipNext  = false;
foreach ($argv as $i => $arg) {
	if ($skipNext) { $skipNext = false; continue; }
	if ($arg === '--config') { $skipNext = true; continue; }
	if (str_starts_with($arg, '--config=')) continue;
	$cleanArgv[] = $arg;
}

$command = $cleanArgv[1] ?? '';

if ($command === '' || $command === 'help' || $command === '--help') {
	usage();
}

if ($command === 'init-config') {
	cmdInitConfig();
	exit(0);
}

$cfg = Config::load($configPath);

match ($command) {
	'new-case'         => cmdNewCase($cfg, $cleanArgv[2] ?? throw new \InvalidArgumentException('Missing case_id')),
	'ingest'           => cmdIngest($cfg, $cleanArgv[2] ?? throw new \InvalidArgumentException('Missing case_id'), $cleanArgv[3] ?? throw new \InvalidArgumentException('Missing path')),
	'reinventory'      => cmdReinventory($cfg, $cleanArgv[2] ?? throw new \InvalidArgumentException('Missing case_id')),
	'run'              => cmdRun($cfg, $cleanArgv[2] ?? throw new \InvalidArgumentException('Missing case_id'), $cleanArgv[3] ?? throw new \InvalidArgumentException('Missing adapter'), array_slice($cleanArgv, 4)),
	'list-adapters'    => cmdListAdapters(),
	'list-files'       => cmdListFiles($cfg, $cleanArgv[2] ?? throw new \InvalidArgumentException('Missing case_id')),
	'status'           => cmdStatus($cfg, $cleanArgv[2] ?? throw new \InvalidArgumentException('Missing case_id')),
	'ledger'           => cmdLedger($cfg, $cleanArgv[2] ?? throw new \InvalidArgumentException('Missing case_id')),
	'test-connections' => cmdTestConnections($cfg),
	'triage'           => cmdTriage($cfg, $cleanArgv[2] ?? throw new \InvalidArgumentException('Missing case_id')),
	'agent'            => cmdAgent($cfg, $cleanArgv[2] ?? throw new \InvalidArgumentException('Missing case_id'), implode(' ', array_slice($cleanArgv, 3))),
	'agent-auto'       => cmdAgentAuto(
		$cfg,
		$cleanArgv[2] ?? throw new \InvalidArgumentException('Missing case_id'),
		implode(' ', array_filter(array_slice($cleanArgv, 3), fn($a) => !str_starts_with($a, '--max-cycles'))),
		(int) (array_reduce($cleanArgv, fn($c, $a) => str_starts_with($a, '--max-cycles=') ? substr($a, 13) : $c, '10')),
	),
	'report'           => cmdReport($cfg, $cleanArgv[2] ?? throw new \InvalidArgumentException('Missing case_id')),
	'kb-index'         => cmdKbIndex($cfg),
	'kb-ingest'        => cmdKbIngest($cfg, $cleanArgv[2] ?? throw new \InvalidArgumentException('Missing file path'), $cleanArgv[3] ?? throw new \InvalidArgumentException('Missing doc_id')),
	'kb-search'        => cmdKbSearch($cfg, implode(' ', array_slice($cleanArgv, 2))),
	'kb-list'          => cmdKbList($cfg),
	'kb-clear'         => cmdKbClear($cfg),
	default            => (function () use ($command) { err("Unknown command: {$command}"); usage(); })(),
};