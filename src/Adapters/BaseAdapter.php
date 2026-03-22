<?php

declare(strict_types=1);

namespace DFIRCopilot\Adapters;

use DFIRCopilot\Case\Workspace;
use DFIRCopilot\Config;
use DFIRCopilot\Executors\ExecResult;

/**
 * Standardised output from any adapter.
 */
final class AdapterResult
{
	public function __construct(
		public readonly string     $adapterName,
		public readonly bool       $success,
		public readonly array      $producedFiles,
		public readonly array      $structuredResults,
		public readonly array      $evidencePointers,
		public readonly string     $stdoutExcerpt,
		public readonly string     $stderrExcerpt,
		public readonly ExecResult $execResult,
		public readonly string     $error = '',
	) {}

	public function toArray(): array
	{
		return [
			'adapter_name'       => $this->adapterName,
			'success'            => $this->success,
			'produced_files'     => $this->producedFiles,
			'structured_results' => $this->structuredResults,
			'evidence_pointers'  => array_slice($this->evidencePointers, 0, 100),
			'stdout_excerpt'     => mb_substr($this->stdoutExcerpt, 0, 3000),
			'stderr_excerpt'     => mb_substr($this->stderrExcerpt, 0, 1000),
			'error'              => $this->error,
		];
	}

	/** Compact JSON for LLM consumption. */
	public function toToolResponse(): string
	{
		return json_encode($this->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
	}
}

// ─────────────────────────────────────────────────────────────────

/**
 * Base class for all DFIR tool adapters.
 *
 * Every adapter must declare:
 *   - NAME, VERSION, DESCRIPTION, TARGET constants
 *   - getToolSchema(): the Ollama function-calling schema
 *   - execute(): the actual logic
 */
abstract class BaseAdapter
{
	public const NAME        = 'base';
	public const VERSION     = '0.0.0';
	public const DESCRIPTION = '';
	public const TARGET      = 'local'; // 'local' | 'remnux' | 'flare'

	abstract public function getToolSchema(): array;

	abstract protected function execute(Workspace $case, Config $config, array $params): AdapterResult;

	/**
	 * Public entry point. Wraps execute() with provenance logging.
	 */
	public function run(Workspace $case, Config $config, array $params = []): AdapterResult
	{
		$start = hrtime(true);

		try {
			$result = $this->execute($case, $config, $params);
		} catch (\Throwable $e) {
			$result = new AdapterResult(
				adapterName: static::NAME,
				success: false,
				producedFiles: [],
				structuredResults: [],
				evidencePointers: [],
				stdoutExcerpt: '',
				stderrExcerpt: '',
				execResult: new ExecResult(-99, '', $e->getMessage(), 0, 'error', ''),
				error: $e->getMessage(),
			);
		}

		$duration = (hrtime(true) - $start) / 1e9;

		// Hash output files for provenance
		$outputHashes = [];
		foreach ($result->producedFiles as $fp) {
			if (file_exists($fp)) {
				$outputHashes[$fp] = hash_file('sha256', $fp);
			}
		}

		$case->logToolRun(
			toolName:          static::NAME,
			toolVersion:       static::VERSION,
			cmdline:           $result->execResult->command,
			inputPaths:        $params['input_paths'] ?? [],
			inputHashes:       [],
			outputPaths:       $result->producedFiles,
			outputHashes:      $outputHashes,
			exitCode:          $result->execResult->exitCode,
			stderrExcerpt:     $result->stderrExcerpt,
			durationSeconds:   $duration,
			structuredResults: $result->structuredResults,
		);

		return $result;
	}

	// ── Helpers for subclasses ───────────────────────────────────

	protected function requireParam(array $params, string $key): string
	{
		if (!isset($params[$key]) || $params[$key] === '') {
			throw new \InvalidArgumentException("Missing required parameter: {$key}");
		}
		return (string) $params[$key];
	}

	protected function resolveFilePath(Workspace $case, string $path): string
	{
		// Absolute path — pass through as-is
		if (str_starts_with($path, '/')) {
			return $path;
		}
		// The model sometimes reads derived paths from tool output (e.g.
		// "cases/test-ls25/derived/foo.txt") and passes them back verbatim.
		// Strip the case dir prefix to avoid "cases/test-ls25/cases/test-ls25/..."
		$caseDir = rtrim($case->caseDir, '/') . '/';
		if (str_starts_with($path, $caseDir)) {
			return $path; // already contains the full relative path from CWD
		}
		return "{$case->caseDir}/{$path}";
	}

	protected function writeJson(string $path, mixed $data): void
	{
		$dir = dirname($path);
		if (!is_dir($dir)) {
			mkdir($dir, 0755, true);
		}
		file_put_contents(
			$path,
			json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
			LOCK_EX
		);
	}

	protected function errorResult(string $msg, string $cmd = ''): AdapterResult
	{
		return new AdapterResult(
			adapterName: static::NAME,
			success: false,
			producedFiles: [],
			structuredResults: [],
			evidencePointers: [],
			stdoutExcerpt: '',
			stderrExcerpt: $msg,
			execResult: new ExecResult(-1, '', $msg, 0, 'local', $cmd),
			error: $msg,
		);
	}
}