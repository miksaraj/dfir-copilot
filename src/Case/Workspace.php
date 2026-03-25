<?php

declare(strict_types=1);

namespace DFIRCopilot\Case;

/**
 * Manages a single case's directory structure, provenance ledger,
 * and case state.
 */
final class Workspace
{
	public readonly string $caseDir;
	public readonly string $rawDir;
	public readonly string $derivedDir;
	public readonly string $iocsDir;
	public readonly string $notesDir;
	public readonly string $timelinesDir;
	public readonly string $ledgerPath;
	public readonly string $statePath;
	public readonly string $inventoryPath;

	public function __construct(
		public readonly string $casesRoot,
		public readonly string $caseId,
	) {
		$this->caseDir       = "{$casesRoot}/{$caseId}";
		$this->rawDir        = "{$this->caseDir}/raw";
		$this->derivedDir    = "{$this->caseDir}/derived";
		$this->iocsDir       = "{$this->caseDir}/iocs";
		$this->notesDir      = "{$this->caseDir}/notes";
		$this->timelinesDir  = "{$this->caseDir}/timelines";
		$this->ledgerPath    = "{$this->caseDir}/ledger.jsonl";
		$this->statePath     = "{$this->caseDir}/case_state.json";
		$this->inventoryPath = "{$this->caseDir}/inventory.json";
	}

	public function create(): self
	{
		foreach (['raw', 'derived', 'iocs', 'notes', 'timelines'] as $sub) {
			$dir = "{$this->caseDir}/{$sub}";
			if (!is_dir($dir)) {
				mkdir($dir, 0755, true);
			}
		}

		if (!file_exists($this->ledgerPath)) {
			touch($this->ledgerPath);
		}

		if (!file_exists($this->statePath)) {
			$state = [
				'case_id'                => $this->caseId,
				'created_at'             => gmdate('c'),
				'hypotheses'             => [],
				'iocs'                   => [],
				'ttps'                   => [],
				'attribution_candidates' => [],
				'open_questions'         => [],
				'tools_run'              => [],
			];
			$this->writeJson($this->statePath, $state);
		}

		return $this;
	}

	// ── Evidence intake ──────────────────────────────────────────

	/**
	 * Rebuild inventory.json by re-hashing every file currently in raw/.
	 * Use this after unzipping evidence in-place without re-running ingest.
	 *
	 * @return array The freshly written inventory structure.
	 */
	public function rebuildInventory(): array
	{
		$files = [];

		if (is_dir($this->rawDir)) {
			$iter = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator($this->rawDir, \FilesystemIterator::SKIP_DOTS),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);

			foreach ($iter as $file) {
				/** @var \SplFileInfo $file */
				$rel     = ltrim(str_replace($this->rawDir, '', $file->getPathname()), '/');
				$files[] = [
					'relative_path' => $rel,
					'sha256'        => hash_file('sha256', $file->getPathname()),
					'size_bytes'    => $file->getSize(),
				];
			}

			usort($files, fn($a, $b) => strcmp($a['relative_path'], $b['relative_path']));
		}

		$inventory = [
			'files'        => $files,
			'ingested_at'  => gmdate('c'),
		];

		$this->writeJson($this->inventoryPath, $inventory);
		return $inventory;
	}

	public function ingestFile(string $sourcePath): array
	{
		$name = basename($sourcePath);
		$dest = "{$this->rawDir}/{$name}";

		// Avoid overwrites
		if (file_exists($dest)) {
			$info = pathinfo($name);
			$i = 1;
			do {
				$dest = sprintf(
					'%s/%s_%d.%s',
					$this->rawDir,
					$info['filename'],
					$i++,
					$info['extension'] ?? ''
				);
			} while (file_exists($dest));
		}

		copy($sourcePath, $dest);

		return [
			'original_name' => $name,
			'stored_as'     => basename($dest),
			'sha256'        => hash_file('sha256', $dest),
			'size_bytes'    => filesize($dest),
			'ingested_at'   => gmdate('c'),
		];
	}

	public function ingestBundle(string $bundlePath): array
	{
		$inventory = [
			'files'       => [],
			'ingested_at' => gmdate('c'),
		];

		if (is_dir($bundlePath)) {
			$iter = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator($bundlePath, \FilesystemIterator::SKIP_DOTS),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);

			foreach ($iter as $file) {
				/** @var \SplFileInfo $file */
				$rel     = ltrim(str_replace($bundlePath, '', $file->getPathname()), '/');
				$destDir = "{$this->rawDir}/" . dirname($rel);
				if (!is_dir($destDir)) {
					mkdir($destDir, 0755, true);
				}
				$dest = "{$destDir}/" . $file->getFilename();
				copy($file->getPathname(), $dest);

				$inventory['files'][] = [
					'relative_path' => $rel,
					'sha256'        => hash_file('sha256', $dest),
					'size_bytes'    => filesize($dest),
				];
			}
		} else {
			$inventory['files'][] = $this->ingestFile($bundlePath);
		}

		$this->writeJson($this->inventoryPath, $inventory);
		return $inventory;
	}

	// ── Provenance ledger ────────────────────────────────────────

	public function logToolRun(
		string $toolName,
		string $toolVersion,
		string $cmdline,
		array  $inputPaths,
		array  $inputHashes,
		array  $outputPaths,
		array  $outputHashes,
		int    $exitCode,
		string $stderrExcerpt = '',
		float  $durationSeconds = 0.0,
		?array $structuredResults = null,
	): array {
		$record = [
			'timestamp'        => gmdate('c'),
			'tool_name'        => $toolName,
			'tool_version'     => $toolVersion,
			'cmdline'          => $cmdline,
			'input_paths'      => $inputPaths,
			'input_hashes'     => $inputHashes,
			'output_paths'     => $outputPaths,
			'output_hashes'    => $outputHashes,
			'exit_code'        => $exitCode,
			'stderr_excerpt'   => mb_substr($stderrExcerpt, 0, 2000),
			'duration_seconds' => round($durationSeconds, 3),
		];

		if ($structuredResults !== null) {
			$record['structured_results_summary'] = mb_substr(
				json_encode($structuredResults),
				0,
				500
			);
		}

		file_put_contents(
			$this->ledgerPath,
			json_encode($record, JSON_UNESCAPED_SLASHES) . "\n",
			FILE_APPEND | LOCK_EX
		);

		return $record;
	}

	// ── Case state ───────────────────────────────────────────────

	public function getState(): array
	{
		if (!file_exists($this->statePath)) {
			return [];
		}
		return json_decode(file_get_contents($this->statePath), true) ?: [];
	}

	public function updateState(array $updates): array
	{
		$state = $this->getState();
		$state = array_merge($state, $updates);
		$state['last_updated'] = gmdate('c');
		$this->writeJson($this->statePath, $state);
		return $state;
	}

	public function addIOC(
		string $type,
		string $value,
		string $confidence,
		string $sourceTool,
		array  $evidencePointers,
	): array {
		$state = $this->getState();
		$ioc = [
			'type'              => $type,
			'value'             => $value,
			'confidence'        => $confidence,
			'source_tool'       => $sourceTool,
			'evidence_pointers' => $evidencePointers,
			'added_at'          => gmdate('c'),
		];
		$state['iocs'][] = $ioc;
		$this->updateState($state);
		return $ioc;
	}

	public function addHypothesis(
		string $statement,
		array  $supporting,
		array  $refuting = [],
	): array {
		$state = $this->getState();
		$hyp = [
			'statement'           => $statement,
			'supporting_evidence' => $supporting,
			'refuting_evidence'   => $refuting,
			'status'              => 'open',
			'added_at'            => gmdate('c'),
		];
		$state['hypotheses'][] = $hyp;
		$this->updateState($state);
		return $hyp;
	}

	// ── Queries ──────────────────────────────────────────────────

	public function listRawFiles(): array
	{
		$files = [];
		if (!is_dir($this->rawDir)) {
			return $files;
		}

		$iter = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator($this->rawDir, \FilesystemIterator::SKIP_DOTS),
			\RecursiveIteratorIterator::LEAVES_ONLY
		);

		foreach ($iter as $file) {
			/** @var \SplFileInfo $file */
			$files[] = [
				'path'       => ltrim(str_replace($this->caseDir, '', $file->getPathname()), '/'),
				'name'       => $file->getFilename(),
				'size_bytes' => $file->getSize(),
			];
		}

		sort($files);
		return $files;
	}

	public function getLedger(): array
	{
		$entries = [];
		if (!file_exists($this->ledgerPath)) {
			return $entries;
		}

		foreach (file($this->ledgerPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
			$decoded = json_decode($line, true);
			if ($decoded !== null) {
				$entries[] = $decoded;
			}
		}

		return $entries;
	}

	// ── Helpers ──────────────────────────────────────────────────

	private function writeJson(string $path, array $data): void
	{
		file_put_contents(
			$path,
			json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
			LOCK_EX
		);
	}
}