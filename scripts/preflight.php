#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * DFIR Copilot — Exercise-Day Preflight Check
 *
 * Run this before the exercise starts to verify everything works.
 * Catches problems when you still have time to fix them.
 *
 * Usage:
 *   php scripts/preflight.php [--config=config.json]
 *
 * Exit codes:
 *   0 = all critical checks passed
 *   1 = one or more critical checks failed
 */

require_once __DIR__ . '/../autoload.php';

use DFIRCopilot\Config;
use DFIRCopilot\Agent\OllamaClient;
use DFIRCopilot\Executors\SSHExecutor;
use DFIRCopilot\Executors\WinRMExecutor;
use DFIRCopilot\Rag\KnowledgeBase;
use DFIRCopilot\Case\Workspace;

// ── CLI ──────────────────────────────────────────────────────────

$configPath = 'config.json';
foreach ($argv as $i => $arg) {
	if (str_starts_with($arg, '--config=')) {
		$configPath = substr($arg, 9);
	}
}

// ── Output helpers ───────────────────────────────────────────────

$criticalFails = 0;
$warnings      = 0;

function ok(string $msg): void { echo "\033[0;32m  ✓\033[0m {$msg}\n"; }
function warn(string $msg): void { global $warnings; $warnings++; echo "\033[1;33m  ⚠\033[0m {$msg}\n"; }
function fail(string $msg): void { global $criticalFails; $criticalFails++; echo "\033[0;31m  ✗\033[0m {$msg}\n"; }
function section(string $msg): void { echo "\n\033[1;37m{$msg}\033[0m\n"; }

echo "\n";
echo "╔══════════════════════════════════════════════════════════╗\n";
echo "║       DFIR Copilot — Exercise-Day Preflight Check       ║\n";
echo "╚══════════════════════════════════════════════════════════╝\n";

// ── 1. Config ────────────────────────────────────────────────────

section("1. Configuration");

if (!file_exists($configPath)) {
	fail("Config file not found: {$configPath}");
	fail("Run: php dfirbus.php init-config");
	exit(1);
}
ok("Config file: {$configPath}");

$cfg = Config::load($configPath);
ok("Config loaded successfully");

// ── 2. PHP extensions ────────────────────────────────────────────

section("2. PHP Environment");

$phpVersion = PHP_VERSION;
if (version_compare($phpVersion, '8.3.0', '>=')) {
	ok("PHP {$phpVersion}");
} else {
	fail("PHP {$phpVersion} — need 8.3+");
}

$requiredExts = ['curl', 'mbstring', 'json'];
foreach ($requiredExts as $ext) {
	if (extension_loaded($ext)) {
		ok("ext-{$ext}");
	} else {
		fail("ext-{$ext} not loaded");
	}
}

if (extension_loaded('ssh2')) {
	ok("ext-ssh2");
} else {
	fail("ext-ssh2 not loaded — REMnux adapters will not work");
	fail("Install: sudo apt install php-ssh2");
}

// ── 3. Ollama ────────────────────────────────────────────────────

section("3. Ollama");

$client = OllamaClient::fromConfig($cfg);
$status = $client->testConnection();

if (!$status['connected']) {
	fail("Ollama not reachable at {$cfg->ollamaBaseUrl}");
	fail("Start it: ollama serve");
} else {
	ok("Ollama connected at {$cfg->ollamaBaseUrl}");

	$models = $status['models'];

	// Worker model
	$workerFound = false;
	foreach ($models as $m) {
		if (str_contains($m, $cfg->ollamaWorkerModel)) {
			$workerFound = true;
			break;
		}
	}
	if ($workerFound) {
		ok("Worker model: {$cfg->ollamaWorkerModel}");
	} else {
		fail("Worker model NOT FOUND: {$cfg->ollamaWorkerModel}");
		fail("Run: ollama pull {$cfg->ollamaWorkerModel}");
	}

	// Judge model
	if ($cfg->isSingleModelMode()) {
		ok("Judge model: same as worker (single-model mode)");
	} else {
		$judgeFound = false;
		foreach ($models as $m) {
			if (str_contains($m, $cfg->ollamaJudgeModel)) {
				$judgeFound = true;
				break;
			}
		}
		if ($judgeFound) {
			ok("Judge model: {$cfg->ollamaJudgeModel}");
		} else {
			fail("Judge model NOT FOUND: {$cfg->ollamaJudgeModel}");
		}
	}

	// Heavy model (optional)
	if ($cfg->hasHeavyModel()) {
		$heavyFound = false;
		foreach ($models as $m) {
			if (str_contains($m, $cfg->ollamaHeavyModel)) {
				$heavyFound = true;
				break;
			}
		}
		if ($heavyFound) {
			ok("Heavy model (optional): {$cfg->ollamaHeavyModel}");
		} else {
			warn("Heavy model not found: {$cfg->ollamaHeavyModel} (optional)");
		}
	}

	// Env vars
	$envChecks = [
		'OLLAMA_KV_CACHE_TYPE'     => $cfg->ollamaKvCacheType,
		'OLLAMA_NUM_PARALLEL'      => '1',
		'OLLAMA_MAX_LOADED_MODELS' => '1',
	];
	foreach ($envChecks as $key => $expected) {
		$actual = getenv($key);
		if ($actual === $expected) {
			ok("{$key}={$expected}");
		} elseif ($actual === false) {
			warn("{$key} not set (recommended: {$expected})");
		} else {
			warn("{$key}={$actual} (recommended: {$expected})");
		}
	}
}

// ── 4. RAG / Knowledge Base ──────────────────────────────────────

section("4. Knowledge Base (RAG)");

try {
	$kb        = KnowledgeBase::fromConfig($cfg);
	$ragStatus = $kb->testConnection();

	if ($ragStatus['connected']) {
		ok("Embedding model: {$cfg->ragEmbeddingModel} ({$ragStatus['dimensions']}d)");
	} else {
		fail("Embedding model not reachable: {$cfg->ragEmbeddingModel}");
		fail("Run: ollama pull {$cfg->ragEmbeddingModel}");
	}

	$chunkCount = $kb->chunkCount();
	$docs       = $kb->listDocuments();

	if ($chunkCount > 0) {
		ok("Knowledge base: {$chunkCount} chunks from " . count($docs) . " documents");
		foreach ($docs as $d) {
			$type = $d['metadata']['type'] ?? '?';
			ok("  {$d['doc_id']}: {$d['chunks']} chunks");
		}
	} else {
		warn("Knowledge base is empty — index scenario CTI before the exercise");
		warn("Place files in {$cfg->ragKnowledgeDir}/ then run: php dfirbus.php kb-index");
	}
} catch (\Throwable $e) {
	warn("Knowledge base: {$e->getMessage()}");
}

if (!is_dir($cfg->ragKnowledgeDir)) {
	warn("Knowledge directory does not exist: {$cfg->ragKnowledgeDir}");
} else {
	// Count files
	$kbFiles = glob("{$cfg->ragKnowledgeDir}/*/*.{md,txt}", GLOB_BRACE) ?: [];
	if (count($kbFiles) > 0) {
		ok(count($kbFiles) . " source files in {$cfg->ragKnowledgeDir}/");
	} else {
		warn("No .md/.txt files in {$cfg->ragKnowledgeDir}/ subdirectories");
	}
}

// ── 5. REMnux SSH ────────────────────────────────────────────────

section("5. REMnux (SSH)");

try {
	$ssh = SSHExecutor::fromConfig($cfg);

	if ($ssh->testConnection()) {
		ok("SSH connected to {$cfg->remnuxHost}");

		// Check key tools
		$tools = [
			'strings'          => 'strings extraction',
			'yara'             => 'YARA scanning',
			'capa'             => 'capability analysis',
			'vol'              => 'Volatility 3 memory forensics',
			'tshark'           => 'PCAP analysis',
			'log2timeline.py'  => 'timeline building',
		];

		foreach ($tools as $bin => $desc) {
			$r = $ssh->run("which {$bin} 2>/dev/null || echo 'NOT_FOUND'");
			if (!str_contains($r->stdout, 'NOT_FOUND')) {
				ok("{$bin} — {$desc}");
			} else {
				warn("{$bin} not found — {$desc} will not work");
			}
		}

		// Check work directory is writable
		$r = $ssh->run("mkdir -p {$cfg->remnuxWorkDir} && touch {$cfg->remnuxWorkDir}/.preflight_test && rm {$cfg->remnuxWorkDir}/.preflight_test && echo 'WRITABLE'");
		if (str_contains($r->stdout, 'WRITABLE')) {
			ok("Work directory writable: {$cfg->remnuxWorkDir}");
		} else {
			fail("Cannot write to {$cfg->remnuxWorkDir} on REMnux");
		}

		// Check disk space
		$r = $ssh->run("df -h {$cfg->remnuxWorkDir} | tail -1 | awk '{print \$4}'");
		$freeSpace = trim($r->stdout);
		if ($freeSpace !== '') {
			ok("Free disk space on REMnux: {$freeSpace}");
		}
	} else {
		fail("Cannot connect to REMnux at {$cfg->remnuxHost}:{$cfg->remnuxPort}");
		if ($cfg->remnuxKeyFile !== '' && !file_exists($cfg->remnuxKeyFile)) {
			fail("SSH key file not found: {$cfg->remnuxKeyFile}");
		}
	}
} catch (\Throwable $e) {
	fail("REMnux SSH: {$e->getMessage()}");
}

// ── 6. FLARE-VM WinRM ────────────────────────────────────────────

section("6. FLARE-VM (WinRM)");

try {
	$winrm = WinRMExecutor::fromConfig($cfg);

	if ($winrm->testConnection()) {
		ok("WinRM connected to {$cfg->flareHost}");

		// Check shared folder if configured
		if ($cfg->flareSharedHostPath !== '') {
			if (is_dir($cfg->flareSharedHostPath)) {
				ok("Shared folder (host side): {$cfg->flareSharedHostPath}");
			} else {
				warn("Shared folder not found: {$cfg->flareSharedHostPath}");
				warn("Create it: mkdir -p {$cfg->flareSharedHostPath}");
			}
		} else {
			warn("No shared folder configured — PE file transfer will require manual copy");
		}
	} else {
		warn("Cannot connect to FLARE-VM at {$cfg->flareHost}:{$cfg->flareWinRMPort}");
		warn("This is optional — PE analysis can be done manually");
	}
} catch (\Throwable $e) {
	warn("FLARE-VM WinRM: {$e->getMessage()}");
}

// ── 7. Case workspace ────────────────────────────────────────────

section("7. Workspace");

if (!is_dir($cfg->casesRoot)) {
	warn("Cases directory does not exist yet: {$cfg->casesRoot} (will be created on first case)");
} else {
	ok("Cases directory: {$cfg->casesRoot}");
}

// Check disk space on host
$freeBytes = disk_free_space(dirname($cfg->casesRoot) ?: '.');
if ($freeBytes !== false) {
	$freeGB = round($freeBytes / (1024 * 1024 * 1024), 1);
	if ($freeGB >= 10) {
		ok("Host disk space: {$freeGB} GB free");
	} elseif ($freeGB >= 5) {
		warn("Host disk space: {$freeGB} GB free (getting tight)");
	} else {
		fail("Host disk space: {$freeGB} GB free (may not be enough for large cases)");
	}
}

// Check YARA rules
if (is_dir($cfg->yaraRulesDir)) {
	$yaraFiles = glob("{$cfg->yaraRulesDir}/*.{yar,yara}", GLOB_BRACE) ?: [];
	if (count($yaraFiles) > 0) {
		ok(count($yaraFiles) . " YARA rule files in {$cfg->yaraRulesDir}/");
	} else {
		warn("No YARA rules in {$cfg->yaraRulesDir}/ — yara_scan will need rules on REMnux");
	}
} else {
	warn("YARA rules directory not found: {$cfg->yaraRulesDir}");
}

// ── Summary ──────────────────────────────────────────────────────

echo "\n";
echo str_repeat('─', 58) . "\n";

if ($criticalFails === 0) {
	echo "\033[0;32m  PREFLIGHT PASSED\033[0m";
	if ($warnings > 0) {
		echo " with {$warnings} warning(s)";
	}
	echo "\n\n";
	echo "  Ready for the exercise. Good luck!\n\n";
	echo "  Quick reference:\n";
	echo "    php dfirbus.php new-case <id>        Create case\n";
	echo "    php dfirbus.php ingest <id> <path>   Ingest evidence\n";
	echo "    php dfirbus.php triage <id>          Quick local triage\n";
	echo "    php dfirbus.php agent <id> \"...\"     Run agent\n";
	echo "    php dfirbus.php report <id>          Generate report\n";
	echo "\n";
	exit(0);
} else {
	echo "\033[0;31m  PREFLIGHT FAILED\033[0m — {$criticalFails} critical issue(s), {$warnings} warning(s)\n\n";
	echo "  Fix the issues marked with ✗ before the exercise starts.\n\n";
	exit(1);
}