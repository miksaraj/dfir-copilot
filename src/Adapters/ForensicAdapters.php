<?php

declare(strict_types=1);

namespace DFIRCopilot\Adapters;

use DFIRCopilot\Case\Workspace;
use DFIRCopilot\Config;
use DFIRCopilot\Executors\ExecResult;
use DFIRCopilot\Executors\SSHExecutor;
use DFIRCopilot\Executors\SharedPath;

// ─────────────────────────────────────────────────────────────────
// email_parse
// ─────────────────────────────────────────────────────────────────

/**
 * Parse a raw RFC-2822 / MIME email (.eml) file.
 *
 * Extracts all Received headers (attacker's originating IP chain),
 * SPF/DKIM/DMARC authentication results, decoded body parts, embedded
 * URLs, and attachment filenames + hashes.  Works on phishing emails
 * and pipeline-notification emails alike.
 *
 * Relevant for: FOR-300 (pipeline compromise email), FOR-400 (phishing
 * initial-access vector), any case with .eml evidence.
 */
final class EmailParse extends BaseAdapter
{
	public const NAME        = 'email_parse';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Parse a raw .eml file: extract Received headers (originating IP chain), SPF/DKIM/DMARC results, decoded body text, embedded URLs, and attachment filenames + SHA-256 hashes. Essential for phishing initial-access and pipeline-compromise investigations.';
	public const TARGET      = 'local';

	public function getToolSchema(): array
	{
		return [
			'name'       => self::NAME,
			'description'=> self::DESCRIPTION,
			'parameters' => [
				'type'       => 'object',
				'properties' => [
					'file_path' => [
						'type'        => 'string',
						'description' => 'Path to .eml file (relative to case dir).',
					],
					'save_attachments' => [
						'type'        => 'boolean',
						'description' => 'If true, save decoded attachment bytes to derived/. Default false.',
						'default'     => false,
					],
				],
				'required' => ['file_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp              = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));
		$saveAttachments = (bool) ($params['save_attachments'] ?? false);

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$raw = file_get_contents($fp);
		if ($raw === false) return $this->errorResult("Cannot read: {$fp}");

		// ── Split headers / body ──────────────────────────────────
		$headerEnd = strpos($raw, "\r\n\r\n") ?: strpos($raw, "\n\n");
		$headerRaw = $headerEnd !== false ? substr($raw, 0, $headerEnd) : $raw;
		$bodyRaw   = $headerEnd !== false ? substr($raw, $headerEnd + ($raw[$headerEnd + 1] === "\n" ? 2 : 4)) : '';

		// Unfold headers (RFC 5322 §2.2.3)
		$headerRaw = preg_replace('/\r?\n[ \t]+/', ' ', $headerRaw) ?? $headerRaw;
		$headerLines = explode("\n", str_replace("\r\n", "\n", $headerRaw));

		$headers = [];
		foreach ($headerLines as $line) {
			if (!str_contains($line, ':')) continue;
			[$name, $val] = explode(':', $line, 2);
			$name = strtolower(trim($name));
			$headers[$name][] = trim($val);
		}

		// ── Received chain → originating IP ──────────────────────
		$received   = [];
		$originIp   = '';
		foreach (array_reverse($headers['received'] ?? []) as $r) {
			$entry = ['raw' => $r];
			if (preg_match('/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/', $r, $m)) {
				$entry['ip'] = $m[1];
				if ($originIp === '') $originIp = $m[1]; // first (outermost) is true origin
			}
			if (preg_match('/;\s*(.+)$/', $r, $m)) $entry['date'] = trim($m[1]);
			$received[] = $entry;
		}

		// ── Auth results ──────────────────────────────────────────
		$authResults = [];
		foreach ($headers['authentication-results'] ?? [] as $ar) {
			if (preg_match('/spf=(pass|fail|neutral|softfail|none)/i',  $ar, $m)) $authResults['spf']   = strtolower($m[1]);
			if (preg_match('/dkim=(pass|fail|neutral|none)/i',           $ar, $m)) $authResults['dkim']  = strtolower($m[1]);
			if (preg_match('/dmarc=(pass|fail|none)/i',                  $ar, $m)) $authResults['dmarc'] = strtolower($m[1]);
		}

		// ── Key headers ───────────────────────────────────────────
		$from       = implode(', ', $headers['from']       ?? []);
		$to         = implode(', ', $headers['to']         ?? []);
		$replyTo    = implode(', ', $headers['reply-to']   ?? []);
		$subject    = implode(', ', $headers['subject']    ?? []);
		$date       = implode(', ', $headers['date']       ?? []);
		$msgId      = implode(', ', $headers['message-id'] ?? []);
		$xOrigIp    = implode(', ', $headers['x-originating-ip'] ?? $headers['x-sender-ip'] ?? []);

		// ── Decode body + extract URLs ─────────────────────────────
		$bodyText  = '';
		$urls      = [];
		$parts     = $this->parseMimeParts($raw);
		foreach ($parts as $part) {
			if (str_contains($part['content_type'], 'text/')) {
				$text = $part['body'];
				if (str_contains($part['encoding'] ?? '', 'base64'))            $text = base64_decode($text);
				elseif (str_contains($part['encoding'] ?? '', 'quoted-printable')) $text = quoted_printable_decode($text);
				$bodyText .= strip_tags($text) . "\n";
			}
		}
		if (preg_match_all('#https?://[^\s<>"\']+#i', $bodyText . $bodyRaw, $m)) {
			$urls = array_unique($m[0]);
		}

		// ── Attachments ────────────────────────────────────────────
		$attachments = [];
		foreach ($parts as $part) {
			$disp = $part['disposition'] ?? '';
			$name = $part['filename']    ?? '';
			if ($name === '' && !str_contains($disp, 'attachment')) continue;
			$decoded  = base64_decode($part['body'], true);
			if ($decoded === false) $decoded = quoted_printable_decode($part['body']);
			$att = [
				'filename'     => $name ?: 'attachment',
				'content_type' => $part['content_type'] ?? 'application/octet-stream',
				'size_bytes'   => strlen($decoded),
				'sha256'       => hash('sha256', $decoded),
				'md5'          => hash('md5',    $decoded),
			];
			if ($saveAttachments && $decoded !== '') {
				$safe    = preg_replace('/[^a-zA-Z0-9._-]/', '_', $att['filename']);
				$outPath = "{$case->derivedDir}/attachment_{$safe}";
				file_put_contents($outPath, $decoded);
				$att['saved_to'] = $outPath;
			}
			$attachments[] = $att;
		}

		// ── Spoofing signals ──────────────────────────────────────
		$spoofFlags = [];
		if (!empty($authResults['spf'])  && $authResults['spf']  !== 'pass') $spoofFlags[] = "SPF:{$authResults['spf']}";
		if (!empty($authResults['dkim']) && $authResults['dkim'] !== 'pass') $spoofFlags[] = "DKIM:{$authResults['dkim']}";
		if ($replyTo !== '' && !str_contains(strtolower($from), explode('@', strtolower($replyTo))[1] ?? '')) {
			$spoofFlags[] = 'reply-to-mismatch';
		}

		// ── Output ────────────────────────────────────────────────
		$stem    = pathinfo($fp, PATHINFO_FILENAME);
		$outPath = "{$case->derivedDir}/email_{$stem}.json";
		$result  = [
			'from'         => $from,
			'to'           => $to,
			'reply_to'     => $replyTo,
			'subject'      => $subject,
			'date'         => $date,
			'message_id'   => $msgId,
			'origin_ip'    => $originIp ?: $xOrigIp,
			'x_orig_ip'    => $xOrigIp,
			'auth_results' => $authResults,
			'spoof_flags'  => $spoofFlags,
			'received_chain' => $received,
			'body_text'    => mb_substr($bodyText, 0, 4000),
			'urls'         => array_values($urls),
			'attachments'  => $attachments,
		];
		$this->writeJson($outPath, $result);

		$evidence = [];
		if ($originIp !== '')       $evidence[] = "email:origin_ip={$originIp}";
		if ($xOrigIp !== '')        $evidence[] = "email:x_orig_ip={$xOrigIp}";
		if (!empty($spoofFlags))    $evidence[] = 'email:spoofing=' . implode(',', $spoofFlags);
		foreach (array_slice($urls, 0, 10) as $u) $evidence[] = 'email:url=' . mb_substr($u, 0, 100);
		foreach ($attachments as $a) $evidence[] = "email:attachment:{$a['filename']}:sha256={$a['sha256']}";

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: $result,
			evidencePointers:  $evidence,
			stdoutExcerpt:     "Email: from={$from}, origin_ip=" . ($originIp ?: $xOrigIp ?: 'n/a') . ', urls=' . count($urls) . ', attachments=' . count($attachments) . ', spoof=' . (empty($spoofFlags) ? 'none' : implode(',', $spoofFlags)),
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', 'email_parse ' . basename($fp)),
		);
	}

	/** Very lightweight MIME part splitter (handles multipart and single-part). */
	private function parseMimeParts(string $raw): array
	{
		$parts = [];
		// Extract Content-Type from root to find boundary
		if (preg_match('/Content-Type:\s*multipart\/[^;]+;\s*boundary="?([^"\r\n]+)"?/i', $raw, $m)) {
			$boundary = trim($m[1]);
			$chunks   = preg_split('/--' . preg_quote($boundary, '/') . '(?:--)?/', $raw) ?: [];
			foreach (array_slice($chunks, 1) as $chunk) {
				$parts[] = $this->parsePartHeaders($chunk);
			}
		} else {
			$parts[] = $this->parsePartHeaders($raw);
		}
		return $parts;
	}

	private function parsePartHeaders(string $chunk): array
	{
		$sep = strpos($chunk, "\r\n\r\n") ?: strpos($chunk, "\n\n");
		$hdr = $sep !== false ? substr($chunk, 0, $sep) : '';
		$body= $sep !== false ? ltrim(substr($chunk, $sep)) : $chunk;

		$ct   = '';
		$enc  = '';
		$disp = '';
		$fn   = '';
		if (preg_match('/Content-Type:\s*([^\r\n;]+)/i',              $hdr, $m)) $ct   = trim($m[1]);
		if (preg_match('/Content-Transfer-Encoding:\s*([^\r\n]+)/i',  $hdr, $m)) $enc  = strtolower(trim($m[1]));
		if (preg_match('/Content-Disposition:\s*([^\r\n;]+)/i',       $hdr, $m)) $disp = trim($m[1]);
		if (preg_match('/(?:filename|name)\*?=["\'"]?([^"\';\r\n]+)/i',$hdr, $m)) $fn  = trim($m[1], '"\'');

		return ['content_type' => $ct, 'encoding' => $enc, 'disposition' => $disp, 'filename' => $fn, 'body' => $body];
	}
}

// ─────────────────────────────────────────────────────────────────
// git_diff_parse
// ─────────────────────────────────────────────────────────────────

/**
 * Parse a unified diff file (commits.diff, patch files) into structured output.
 *
 * Reconstructs: list of modified files, per-file added/removed line counts,
 * the actual changed hunks, and a scan of added lines for IOC patterns
 * (URLs, IPs, base64, suspicious strings) — exposing the exact supply-chain
 * modification inserted by the attacker.
 *
 * Relevant for: FOR-800 (GitHub commits.diff contains the backdoor change).
 */
final class GitDiffParse extends BaseAdapter
{
	public const NAME        = 'git_diff_parse';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Parse a unified diff / git patch file into structured hunks. Returns files changed, lines added/removed, and scans added lines for IOCs (URLs, IPs, base64 blobs, suspicious tokens). Essential for supply-chain investigations where a commits.diff contains the attacker\'s modification.';
	public const TARGET      = 'local';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'file_path' => [
						'type'        => 'string',
						'description' => 'Path to the .diff / .patch file (relative to case dir).',
					],
					'ioc_scan' => [
						'type'        => 'boolean',
						'description' => 'If true (default), scan added lines for URLs, IPs, hashes, base64 blobs.',
						'default'     => true,
					],
					'max_hunk_lines' => [
						'type'        => 'integer',
						'description' => 'Maximum lines to return per hunk (default: 100).',
						'default'     => 100,
					],
				],
				'required' => ['file_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp           = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));
		$iocScan      = (bool) ($params['ioc_scan'] ?? true);
		$maxHunkLines = (int) ($params['max_hunk_lines'] ?? 100);

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$lines    = file($fp, FILE_IGNORE_NEW_LINES) ?: [];
		$files    = [];
		$curFile  = null;
		$curHunk  = null;
		$addedLines = [];

		foreach ($lines as $line) {
			if (str_starts_with($line, 'diff --git ')) {
				if ($curFile !== null) {
					if ($curHunk !== null) $curFile['hunks'][] = $curHunk;
					$files[] = $curFile;
				}
				// Extract b/ filename
				if (preg_match('#diff --git a/.+ b/(.+)$#', $line, $m)) {
					$curFile = ['file' => $m[1], 'added' => 0, 'removed' => 0, 'hunks' => []];
				}
				$curHunk = null;
				continue;
			}
			if (str_starts_with($line, '--- ') || str_starts_with($line, '+++ ')) continue;
			if (str_starts_with($line, '@@') && $curFile !== null) {
				if ($curHunk !== null) $curFile['hunks'][] = $curHunk;
				$curHunk = ['header' => $line, 'lines' => []];
				continue;
			}
			if ($curFile !== null && $curHunk !== null) {
				if (count($curHunk['lines']) < $maxHunkLines) $curHunk['lines'][] = $line;
				if (str_starts_with($line, '+')) { $curFile['added']++; $addedLines[] = substr($line, 1); }
				if (str_starts_with($line, '-')) $curFile['removed']++;
			}
		}
		if ($curFile !== null) {
			if ($curHunk !== null) $curFile['hunks'][] = $curHunk;
			$files[] = $curFile;
		}

		// ── IOC scan on added lines ────────────────────────────────
		$iocs = ['urls' => [], 'ips' => [], 'base64' => [], 'suspicious' => []];
		if ($iocScan) {
			$addedText = implode("\n", $addedLines);
			if (preg_match_all('#https?://[^\s\'"<>]+#i', $addedText, $m)) $iocs['urls'] = array_unique($m[0]);
			if (preg_match_all('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $addedText, $m))          $iocs['ips']  = array_unique($m[0]);
			// Flag long base64-looking blobs (≥40 chars)
			if (preg_match_all('/[A-Za-z0-9+\/]{40,}={0,2}/', $addedText, $m))            $iocs['base64'] = array_slice(array_unique($m[0]), 0, 10);
			// Suspicious tokens
			foreach (['exec(', 'eval(', 'base64_decode', 'system(', 'curl ', 'wget ', 'nc ', 'ncat ', '/dev/tcp'] as $tok) {
				if (str_contains($addedText, $tok)) $iocs['suspicious'][] = $tok;
			}
		}

		$summary = [
			'total_files'   => count($files),
			'total_added'   => array_sum(array_column($files, 'added')),
			'total_removed' => array_sum(array_column($files, 'removed')),
			'files'         => $files,
			'iocs'          => $iocs,
		];

		$stem    = pathinfo($fp, PATHINFO_FILENAME);
		$outPath = "{$case->derivedDir}/diff_{$stem}.json";
		$this->writeJson($outPath, $summary);

		$evidence = [];
		foreach ($files as $f) $evidence[] = "diff:file={$f['file']}:+{$f['added']}/-{$f['removed']}";
		foreach ($iocs['urls']       as $u) $evidence[] = 'diff:ioc:url=' . mb_substr($u, 0, 80);
		foreach ($iocs['ips']        as $i) $evidence[] = "diff:ioc:ip={$i}";
		foreach ($iocs['suspicious'] as $s) $evidence[] = "diff:ioc:suspicious={$s}";

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($files),
			producedFiles:     [$outPath],
			structuredResults: $summary,
			evidencePointers:  $evidence,
			stdoutExcerpt:     "Diff: {$summary['total_files']} files, +{$summary['total_added']}/-{$summary['total_removed']} lines, ioc_urls=" . count($iocs['urls']) . ', suspicious=' . implode(',', $iocs['suspicious']),
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', 'git_diff_parse ' . basename($fp)),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// ci_log_parse
// ─────────────────────────────────────────────────────────────────

/**
 * Parse GitHub Actions log ZIP archives.
 *
 * Each GitHub Actions run produces a ZIP containing one .txt log file per job.
 * This adapter extracts any number of those ZIPs, merges all job logs, and lets
 * the analyst filter by step name, error pattern, or keyword — reconstructing
 * the exact build step at which tampered artefacts were injected or secrets leaked.
 *
 * Relevant for: FOR-800 (Actions Logs/logs_*.zip).
 */
final class CiLogParse extends BaseAdapter
{
	public const NAME        = 'ci_log_parse';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Parse GitHub Actions log ZIP archives. Extracts and merges all job .txt logs, reconstructs the step sequence with timestamps, and filters by step name, keyword, or error pattern. Identifies which build step injected tampered artefacts or leaked secrets.';
	public const TARGET      = 'local';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'log_dir' => [
						'type'        => 'string',
						'description' => 'Directory containing the Actions log ZIP archives (relative to case dir).',
					],
					'zip_path' => [
						'type'        => 'string',
						'description' => 'Path to a single Actions log ZIP (alternative to log_dir).',
					],
					'keywords' => [
						'type'        => 'array',
						'items'       => ['type' => 'string'],
						'description' => 'Filter: only return log lines containing any of these keywords (case-insensitive).',
					],
					'error_only' => [
						'type'        => 'boolean',
						'description' => 'If true, only return lines containing "error", "failed", or "exit code" patterns.',
						'default'     => false,
					],
					'max_lines' => [
						'type'        => 'integer',
						'description' => 'Maximum matched lines to return across all logs (default: 500).',
						'default'     => 500,
					],
				],
				'required' => [],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$logDir   = isset($params['log_dir'])  ? $this->resolveFilePath($case, $params['log_dir'])  : '';
		$zipPath  = isset($params['zip_path']) ? $this->resolveFilePath($case, $params['zip_path']) : '';
		$keywords = array_map('strtolower', $params['keywords'] ?? []);
		$errOnly  = (bool) ($params['error_only'] ?? false);
		$maxLines = (int) ($params['max_lines'] ?? 500);

		if (!extension_loaded('zip')) return $this->errorResult('PHP zip extension not loaded. Install php-zip.');

		// Collect ZIP files to process
		$zipFiles = [];
		if ($zipPath !== '' && file_exists($zipPath)) {
			$zipFiles[] = $zipPath;
		} elseif ($logDir !== '' && is_dir($logDir)) {
			foreach (glob("{$logDir}/*.zip") ?: [] as $z) $zipFiles[] = $z;
		} else {
			return $this->errorResult('Provide log_dir (directory of ZIPs) or zip_path (single ZIP).');
		}

		if (empty($zipFiles)) return $this->errorResult('No ZIP files found.');

		$allMatches  = [];
		$stepSummary = [];
		$filesSeen   = [];

		foreach ($zipFiles as $zp) {
			$zip = new \ZipArchive();
			if ($zip->open($zp) !== true) continue;

			$zipBase = basename($zp);
			for ($i = 0; $i < $zip->numFiles; $i++) {
				$name = $zip->getNameIndex($i);
				if (!str_ends_with($name, '.txt')) continue;

				$content = $zip->getFromIndex($i);
				if ($content === false) continue;

				$filesSeen[] = $zipBase . '/' . $name;
				$lines       = explode("\n", str_replace("\r\n", "\n", $content));

				// Extract step boundaries (GitHub format: "##[group]Run stepname")
				$currentStep = $name;
				foreach ($lines as $idx => $line) {
					if (preg_match('/##\[group\](.+)/', $line, $m)) $currentStep = trim($m[1]);

					$stepSummary[$currentStep] = ($stepSummary[$currentStep] ?? 0) + 1;

					// Apply filters
					$lower   = strtolower($line);
					$include = true;
					if ($errOnly && !preg_match('/error|fail(?:ed)?|exit\s*code\s*[^0]/i', $line)) $include = false;
					if ($include && !empty($keywords)) {
						$include = false;
						foreach ($keywords as $kw) {
							if (str_contains($lower, $kw)) { $include = true; break; }
						}
					}
					if ($include && count($allMatches) < $maxLines) {
						$allMatches[] = [
							'zip'  => $zipBase,
							'job'  => $name,
							'step' => $currentStep,
							'line' => $idx + 1,
							'text' => rtrim($line),
						];
					}
				}
			}
			$zip->close();
		}

		$outPath = "{$case->derivedDir}/ci_log_parse.json";
		$this->writeJson($outPath, [
			'zips_processed' => count($zipFiles),
			'files_seen'     => $filesSeen,
			'step_summary'   => $stepSummary,
			'matched_lines'  => count($allMatches),
			'lines'          => $allMatches,
		]);

		$evidence = [];
		foreach (array_slice($allMatches, 0, 20) as $m) {
			$evidence[] = 'ci_log:step=' . mb_substr($m['step'], 0, 60) . ':' . mb_substr($m['text'], 0, 80);
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($allMatches),
			producedFiles:     [$outPath],
			structuredResults: ['zips' => count($zipFiles), 'matched' => count($allMatches), 'steps' => $stepSummary, 'lines' => array_slice($allMatches, 0, 50)],
			evidencePointers:  $evidence,
			stdoutExcerpt:     "CI Logs: " . count($zipFiles) . " ZIPs, " . count($allMatches) . " matches across " . count($stepSummary) . " steps",
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', 'ci_log_parse'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// pipeline_log_parse
// ─────────────────────────────────────────────────────────────────

/**
 * Parse custom CI/CD platform evidence: pipeline logs, event_history CSV,
 * and repo_metadata JSON — as found in FOR-300's CodeForge evidence.
 *
 * Also handles any CSV-format event log with timestamp, user, action columns.
 *
 * Relevant for: FOR-300 (codeforge_pipelines_logs/, event_history.csv,
 * repo_metadata.json).
 */
final class PipelineLogParse extends BaseAdapter
{
	public const NAME        = 'pipeline_log_parse';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Parse CodeForge/custom CI pipeline evidence: event_history CSV (with timestamp/user/action columns), repo_metadata JSON, and plain pipeline log files. Filters by user, repository, action type, or time window. Reconstructs which pipeline run introduced a malicious commit and which user triggered it.';
	public const TARGET      = 'local';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'file_path' => [
						'type'        => 'string',
						'description' => 'Path to event_history CSV, repo_metadata JSON, or a pipeline log file (relative to case dir).',
					],
					'user_filter' => [
						'type'        => 'string',
						'description' => 'Filter: only return events by this username (case-insensitive).',
					],
					'repo_filter' => [
						'type'        => 'string',
						'description' => 'Filter: only return events for this repository name (substring match).',
					],
					'action_filter' => [
						'type'        => 'string',
						'description' => 'Filter: only return events matching this action type (substring, case-insensitive).',
					],
					'time_from' => [
						'type'        => 'string',
						'description' => 'Start time filter (ISO-8601 or YYYY-MM-DD).',
					],
					'time_to' => [
						'type'        => 'string',
						'description' => 'End time filter (ISO-8601 or YYYY-MM-DD).',
					],
					'max_rows' => [
						'type'        => 'integer',
						'description' => 'Maximum rows to return (default: 300).',
						'default'     => 300,
					],
				],
				'required' => ['file_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp           = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));
		$userFilter   = strtolower($params['user_filter']   ?? '');
		$repoFilter   = strtolower($params['repo_filter']   ?? '');
		$actionFilter = strtolower($params['action_filter'] ?? '');
		$timeFrom     = $params['time_from'] ?? '';
		$timeTo       = $params['time_to']   ?? '';
		$maxRows      = (int) ($params['max_rows'] ?? 300);

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ext     = strtolower(pathinfo($fp, PATHINFO_EXTENSION));
		$matched = [];
		$meta    = [];

		if ($ext === 'json') {
			// repo_metadata.json or similar
			$data = json_decode(file_get_contents($fp), true);
			if (!is_array($data)) return $this->errorResult("Invalid JSON: {$fp}");
			$meta    = ['type' => 'json', 'keys' => array_keys($data)];
			$matched = is_array($data) && isset($data[0]) ? $data : [$data];
		} elseif ($ext === 'csv') {
			$handle = fopen($fp, 'r');
			if (!$handle) return $this->errorResult("Cannot open: {$fp}");
			$header = fgetcsv($handle) ?: [];
			$header = array_map(fn($h) => strtolower(trim($h)), $header);

			// Map common column name variations
			$colTs     = $this->findCol($header, ['timestamp', 'time', 'date', 'created_at', 'event_time']);
			$colUser   = $this->findCol($header, ['user', 'username', 'actor', 'author']);
			$colRepo   = $this->findCol($header, ['repo', 'repository', 'project']);
			$colAction = $this->findCol($header, ['action', 'event', 'type', 'event_type']);

			$tsFrom = $timeFrom !== '' ? strtotime($timeFrom) : 0;
			$tsTo   = $timeTo   !== '' ? strtotime($timeTo . ' 23:59:59') : PHP_INT_MAX;

			while (($row = fgetcsv($handle)) !== false) {
				if (count($row) !== count($header)) continue;
				$assoc = array_combine($header, $row);
				if (!$assoc) continue;

				$ts     = $colTs     !== null ? strtotime($assoc[$header[$colTs]] ?? '') : null;
				$user   = strtolower($assoc[$header[$colUser]]   ?? '');
				$repo   = strtolower($assoc[$header[$colRepo]]   ?? '');
				$action = strtolower($assoc[$header[$colAction]] ?? '');

				if ($ts !== null && $ts !== false) {
					if ($ts < $tsFrom || $ts > $tsTo) continue;
				}
				if ($userFilter   !== '' && !str_contains($user,   $userFilter))   continue;
				if ($repoFilter   !== '' && !str_contains($repo,   $repoFilter))   continue;
				if ($actionFilter !== '' && !str_contains($action, $actionFilter)) continue;

				if (count($matched) < $maxRows) $matched[] = $assoc;
			}
			fclose($handle);
			$meta = ['type' => 'csv', 'columns' => $header, 'total_returned' => count($matched)];
		} else {
			// Plain text pipeline log
			$lines = file($fp, FILE_IGNORE_NEW_LINES) ?: [];
			foreach ($lines as $idx => $line) {
				$lower = strtolower($line);
				if ($userFilter   !== '' && !str_contains($lower, $userFilter))   continue;
				if ($repoFilter   !== '' && !str_contains($lower, $repoFilter))   continue;
				if ($actionFilter !== '' && !str_contains($lower, $actionFilter)) continue;
				if (count($matched) < $maxRows) $matched[] = ['line' => $idx + 1, 'text' => $line];
			}
			$meta = ['type' => 'text', 'total_lines' => count($lines)];
		}

		$stem    = pathinfo($fp, PATHINFO_FILENAME);
		$outPath = "{$case->derivedDir}/pipeline_{$stem}.json";
		$this->writeJson($outPath, ['meta' => $meta, 'rows' => $matched]);

		$evidence = [];
		foreach (array_slice($matched, 0, 20) as $r) {
			$evidence[] = 'pipeline:' . mb_substr(json_encode($r), 0, 120);
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($matched),
			producedFiles:     [$outPath],
			structuredResults: ['meta' => $meta, 'matched' => count($matched), 'rows' => array_slice($matched, 0, 40)],
			evidencePointers:  array_slice($evidence, 0, 30),
			stdoutExcerpt:     "Pipeline log ({$meta['type']}): " . count($matched) . " matched rows from " . basename($fp),
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', 'pipeline_log_parse ' . basename($fp)),
		);
	}

	private function findCol(array $header, array $candidates): ?int
	{
		foreach ($candidates as $c) {
			$idx = array_search($c, $header, true);
			if ($idx !== false) return (int) $idx;
		}
		return null;
	}
}

// ─────────────────────────────────────────────────────────────────
// lua_script_analyse
// ─────────────────────────────────────────────────────────────────
final class LuaScriptAnalyse extends BaseAdapter
{
	public const NAME        = 'lua_script_analyse';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Analyse a Lua-based implant bundle: strings-extract lua.exe/dll, parse conf.txt for C2 config (IPs, ports, keys, URLs), attempt bytecode decompilation via unluac/luadec on REMnux.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name' => self::NAME, 'description' => self::DESCRIPTION,
			'parameters' => ['type' => 'object', 'properties' => [
				'file_path' => ['type' => 'string', 'description' => 'Path to lua.exe, lua51.dll, .lua, .luac, or conf.txt (relative to case dir).'],
				'conf_path' => ['type' => 'string', 'description' => 'Optional separate conf.txt to parse for C2 indicators.'],
			], 'required' => ['file_path']],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp  = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));
		$cfp = isset($params['conf_path']) ? $this->resolveFilePath($case, $params['conf_path']) : '';
		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh = remnux_ssh($config); $rd = $config->remnuxWorkDir; $ssh->run("mkdir -p '{$rd}'");
		$t   = SharedPath::ensureOnREMnux($fp, $config, $ssh, $rd);
		$rp  = $t['path']; $st = pathinfo($fp, PATHINFO_FILENAME); $ex = strtolower(pathinfo($fp, PATHINFO_EXTENSION));
		$res = []; $ev = [];

		// strings
		$rs = "{$rd}/{$st}_strs.txt";
		$ssh->run("strings -n 6 '{$rp}' > '{$rs}' && strings -n 6 -el '{$rp}' >> '{$rs}'", 60);
		$ls = "{$case->derivedDir}/{$st}_lua_strings.txt"; $ssh->copyFrom($rs, $ls); $ssh->run("rm -f '{$rs}'");
		if (file_exists($ls)) {
			$sl = file($ls, FILE_IGNORE_NEW_LINES) ?: []; $res['string_count'] = count($sl);
			$iocs = array_values(array_filter($sl, fn($l) => preg_match('#(https?://|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|:\d{4,5}$)#i', $l)));
			$res['ioc_strings'] = array_slice($iocs, 0, 50);
			foreach (array_slice($iocs, 0, 20) as $s) $ev[] = 'lua:ioc=' . mb_substr($s, 0, 80);
		}

		// decompile
		if (in_array($ex, ['luac','lua',''], true)) {
			$rdec = "{$rd}/{$st}_dec.lua";
			$ssh->run("if command -v java &>/dev/null && [ -f /opt/unluac/unluac.jar ]; then java -jar /opt/unluac/unluac.jar '{$rp}' > '{$rdec}' 2>/dev/null; elif command -v luadec &>/dev/null; then luadec '{$rp}' > '{$rdec}' 2>/dev/null; fi", 30);
			$ldec = "{$case->derivedDir}/{$st}_decompiled.lua"; $ssh->copyFrom($rdec, $ldec); $ssh->run("rm -f '{$rdec}'");
			if (file_exists($ldec) && filesize($ldec) > 0) { $res['decompiled'] = mb_substr(file_get_contents($ldec), 0, 4000); $ev[] = 'lua:decompiled=yes'; }
		}

		// conf
		$cf = ($cfp !== '' && file_exists($cfp)) ? $cfp : (file_exists(dirname($fp) . '/conf.txt') ? dirname($fp) . '/conf.txt' : '');
		if ($cf !== '') {
			$cr = [];
			foreach (explode("\n", str_replace("\r\n", "\n", file_get_contents($cf) ?? '')) as $line) {
				$line = trim($line);
				if ($line === '' || str_starts_with($line, '#') || str_starts_with($line, '--')) continue;
				if (preg_match('/^([A-Za-z_]\w*)\s*[=:]\s*(.+)$/', $line, $m)) {
					$k = trim($m[1]); $v = trim($m[2], '"\''); $cr[$k] = $v;
					if (preg_match('/ip|host|addr|server|c2|url|key|pass|secret|token|port/i', $k)) $ev[] = "lua:conf:{$k}=" . mb_substr($v, 0, 60);
				}
			}
			$res['conf_parsed'] = $cr;
		}
		if ($t['method'] === 'sftp') $ssh->run("rm -f '{$rp}'");
		$out = "{$case->derivedDir}/{$st}_lua_analysis.json"; $this->writeJson($out, $res);
		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($res),
			producedFiles:     array_values(array_filter([$out, $ls ?? ''])),
			structuredResults: $res,
			evidencePointers:  $ev,
			stdoutExcerpt:     "Lua: strings=" . ($res['string_count'] ?? 0) . ", iocs=" . count($res['ioc_strings'] ?? []) . ", conf=" . count($res['conf_parsed'] ?? []) . ", decompiled=" . (isset($res['decompiled']) ? 'yes' : 'no'),
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, "ssh:{$config->remnuxHost}", 'lua_script_analyse'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// lnk_and_jumplist_parse
// ─────────────────────────────────────────────────────────────────
final class LnkAndJumplistParse extends BaseAdapter
{
	public const NAME        = 'lnk_and_jumplist_parse';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Parse Windows Shell Link (.lnk) files from a KAPE-extracted directory. Returns target paths, volume serial numbers, and timestamps — confirms remote share access, USB usage, and attacker file-open history.';
	public const TARGET      = 'remnux';

	private const PARSER = 'import struct,sys,os,json,glob,datetime
def ft(ts):
if not ts: return None
return (datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=ts//10)).strftime("%Y-%m-%dT%H:%M:%SZ")
def parse(path):
try:
with open(path,"rb") as f: d=f.read(1024)
if len(d)<76 or d[:4]!=b"L\x00\x00\x00": return None
		fl=struct.unpack_from("<I",d,20)[0]
		r={"file":os.path.basename(path),"size":struct.unpack_from("<I",d,52)[0],"created":ft(struct.unpack_from("<Q",d,28)[0]),"modified":ft(struct.unpack_from("<Q",d,44)[0])}
		off=76
		if fl&1: off=78+(struct.unpack_from("<H",d,76)[0] if len(d)>78 else 0)
		if fl&2 and len(d)>off+28:
			li=struct.unpack_from("<I",d,off)[0]
			try:
				vo=struct.unpack_from("<I",d,off+12)[0]; r["vsn"]=hex(struct.unpack_from("<I",d,off+vo+8)[0])
				bo=struct.unpack_from("<I",d,off+16)[0]; r["path"]=d[off+bo:].split(b"\x00")[0].decode("latin-1","replace")
			except: pass
		return r
	except: return None
src=sys.argv[1]
files=glob.glob(os.path.join(src,"**","*.lnk"),recursive=True)[:300] if os.path.isdir(src) else [src]
res=[r for f in files if (r:=parse(f))]
res.sort(key=lambda x:x.get("modified") or "",reverse=True)
print(json.dumps(res,indent=2))';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => ['type' => 'object', 'properties' => [
				'path'        => ['type' => 'string', 'description' => 'Path to a .lnk file or directory of .lnk files (relative to case dir).'],
				'date_filter' => ['type' => 'string', 'description' => 'Show entries modified on this date (YYYY-MM-DD).'],
			], 'required' => ['path']],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp = $this->resolveFilePath($case, $this->requireParam($params, 'path'));
		$df = trim($params['date_filter'] ?? '');
		if (!file_exists($fp) && !is_dir($fp)) return $this->errorResult("Path not found: {$fp}");

		$ssh = remnux_ssh($config); $rd = $config->remnuxWorkDir; $ssh->run("mkdir -p '{$rd}'");
		$pr  = "{$rd}/dfircop_lnk.py";
		$pyContent = self::PARSER;
		$ssh->run("python3 -c " . escapeshellarg($pyContent) . " --check 2>/dev/null; cat > '{$pr}' << 'PYEOF'\n{$pyContent}\nPYEOF");

		$rt = "{$rd}/lnk_src";
		if (is_dir($fp)) {
			$ssh->run("mkdir -p '{$rt}'");
			foreach (array_slice(array_merge(glob("{$fp}/*.lnk") ?: [], glob("{$fp}/*.LNK") ?: []), 0, 300) as $lf) $ssh->copyTo($lf, "{$rt}/" . basename($lf));
		} else { $ssh->copyTo($fp, $rt); }

		$r    = $ssh->run("python3 '{$pr}' '{$rt}' 2>/dev/null", 60);
		$data = json_decode($r->stdout, true) ?? [];
		$ssh->run("rm -rf '{$rt}' '{$pr}'");
		if ($df !== '') $data = array_values(array_filter($data, fn($e) => str_starts_with($e['modified'] ?? '', $df)));

		$out = "{$case->derivedDir}/lnk_parse.json"; $this->writeJson($out, $data);
		$ev  = [];
		foreach (array_slice($data, 0, 30) as $e) {
			if (!empty($e['path'])) $ev[] = "lnk:{$e['file']}:path={$e['path']}";
			if (!empty($e['vsn']))  $ev[] = "lnk:{$e['file']}:vsn={$e['vsn']}";
		}
		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($data),
			producedFiles:     [$out],
			structuredResults: ['count' => count($data), 'entries' => array_slice($data, 0, 50)],
			evidencePointers:  $ev,
			stdoutExcerpt:     "LNK: " . count($data) . " entries" . ($df ? " (filter: {$df})" : ''),
			stderrExcerpt:     mb_substr($r->stderr, 0, 300),
			execResult:        new ExecResult(0, '', '', 0, "ssh:{$config->remnuxHost}", 'lnk_and_jumplist_parse'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// linux_artefact_parse
// ─────────────────────────────────────────────────────────────────
final class LinuxArtefactParse extends BaseAdapter
{
	public const NAME        = 'linux_artefact_parse';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Parse Linux forensic artefacts from a filesystem dump directory: auth.log (SSH/sudo), bash_history, crontabs, systemd units, authorized_keys, /etc/passwd, dpkg.log. Essential for builder/server compromise investigations.';
	public const TARGET      = 'local';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => ['type' => 'object', 'properties' => [
				'root_path' => ['type' => 'string', 'description' => 'Root of the Linux filesystem dump (e.g. "raw/evidence/builder01"). Relative to case dir.'],
				'artefacts' => ['type' => 'array', 'items' => ['type' => 'string'], 'description' => 'Types: auth_log, bash_history, crontab, systemd_units, authorized_keys, passwd, dpkg_log. Default: all.'],
				'keywords'  => ['type' => 'array', 'items' => ['type' => 'string'], 'description' => 'Extra keywords to flag in log lines.'],
				'time_from' => ['type' => 'string', 'description' => 'Only include entries on/after this date (YYYY-MM-DD).'],
			], 'required' => ['root_path']],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$root   = $this->resolveFilePath($case, $this->requireParam($params, 'root_path'));
		$wanted = $params['artefacts'] ?? ['auth_log','bash_history','crontab','systemd_units','authorized_keys','passwd','dpkg_log'];
		$kws    = array_map('strtolower', $params['keywords'] ?? []);
		$tf     = $params['time_from'] ?? '';
		$want   = fn(string $t) => in_array($t, $wanted, true);

		if (!is_dir($root)) return $this->errorResult("Directory not found: {$root}");
		$res = []; $ev = [];

		if ($want('auth_log')) {
			$af = array_merge(glob("{$root}/var/log/auth.log*") ?: [], glob("{$root}/var/log/secure*") ?: []);
			$al = [];
			foreach ($af as $f) {
				$lines = str_ends_with($f, '.gz') ? explode("\n", gzdecode(file_get_contents($f) ?: '') ?: '') : (file($f, FILE_IGNORE_NEW_LINES) ?: []);
				foreach ($lines as $l) {
					if ($tf !== '' && substr($l, 0, 10) < $tf) continue;
					$hit = (bool) preg_match('/sshd|sudo|su\b|pam_unix|invalid user|accepted|failed/i', $l);
					if (!$hit && !empty($kws)) foreach ($kws as $kw) if (str_contains(strtolower($l), $kw)) { $hit = true; break; }
					if ($hit) $al[] = $l;
				}
			}
			$al = array_unique(array_slice($al, 0, 500));
			$res['auth_log'] = ['files' => count($af), 'matched' => count($al), 'lines' => array_slice($al, 0, 100)];
			foreach ($al as $l) {
				if (preg_match('/Accepted \S+ for (\S+) from (\S+)/i', $l, $m)) $ev[] = "linux:ssh_ok:user={$m[1]}:ip={$m[2]}";
				if (preg_match('/sudo.*COMMAND=(.*)/i', $l, $m))                 $ev[] = 'linux:sudo:' . mb_substr(trim($m[1]), 0, 80);
			}
		}

		if ($want('bash_history')) {
			$hf = array_merge(glob("{$root}/home/*/.bash_history") ?: [], glob("{$root}/root/.bash_history") ?: []);
			$hists = [];
			foreach ($hf as $f) {
				$user = basename(dirname($f)); $lines = file($f, FILE_IGNORE_NEW_LINES) ?: [];
				$hists[$user] = array_slice($lines, -200);
				foreach (array_slice($lines, -50) as $cmd) if (preg_match('/curl|wget|nc |ncat|python|perl|bash -c|chmod\s*\+x|base64|ssh-keygen|useradd/i', $cmd)) $ev[] = 'linux:bash:' . mb_substr($cmd, 0, 100);
			}
			$res['bash_history'] = $hists;
		}

		if ($want('crontab')) {
			$cf = array_merge(glob("{$root}/var/spool/cron/crontabs/*") ?: [], glob("{$root}/etc/cron.d/*") ?: [], (array)(glob("{$root}/etc/crontab") ?: []));
			$crons = [];
			foreach ($cf as $f) {
				$lines = array_values(array_filter(file($f, FILE_IGNORE_NEW_LINES) ?: [], fn($l) => trim($l) !== '' && !str_starts_with(trim($l), '#')));
				if (!empty($lines)) { $crons[basename($f)] = $lines; $ev[] = 'linux:crontab:' . basename($f); }
			}
			$res['crontab'] = $crons;
		}

		if ($want('systemd_units')) {
			$uf = array_merge(glob("{$root}/etc/systemd/system/*.service") ?: [], glob("{$root}/usr/lib/systemd/system/*.service") ?: []);
			$units = [];
			foreach ($uf as $f) {
				$c = file_get_contents($f) ?: '';
				if (preg_match('/ExecStart\s*=\s*(.+)/i', $c, $m) && !preg_match('#^/usr/(bin|sbin|lib)/#', trim($m[1]))) {
					$exec = trim($m[1]); $units[basename($f)] = ['exec_start' => $exec]; $ev[] = "linux:systemd:" . basename($f) . ":" . mb_substr($exec, 0, 80);
				}
			}
			$res['systemd_units'] = $units;
		}

		if ($want('authorized_keys')) {
			$ak = array_merge(glob("{$root}/home/*/.ssh/authorized_keys") ?: [], glob("{$root}/root/.ssh/authorized_keys") ?: []);
			$keys = [];
			foreach ($ak as $f) {
				$user = basename(dirname(dirname($f)));
				$lines = array_values(array_filter(file($f, FILE_IGNORE_NEW_LINES) ?: [], fn($l) => trim($l) !== '' && !str_starts_with($l, '#')));
				$keys[$user] = $lines;
				foreach ($lines as $l) $ev[] = "linux:auth_key:{$user}:" . mb_substr(implode(' ', array_slice(explode(' ', $l), 2)), 0, 60);
			}
			$res['authorized_keys'] = $keys;
		}

		if ($want('passwd') && file_exists("{$root}/etc/passwd")) {
			$users = [];
			foreach (file("{$root}/etc/passwd", FILE_IGNORE_NEW_LINES) ?: [] as $line) {
				[$user,,$uid,,$comment,$home,$shell] = array_pad(explode(':', $line), 7, '');
				if ((int)$uid >= 1000 || $user === 'root') { $users[] = compact('user','uid','comment','home','shell'); if ((int)$uid >= 1000) $ev[] = "linux:user:{$user}:uid={$uid}"; }
			}
			$res['passwd'] = $users;
		}

		if ($want('dpkg_log')) {
			$ins = [];
			foreach (glob("{$root}/var/log/dpkg.log*") ?: [] as $f) foreach (file($f, FILE_IGNORE_NEW_LINES) ?: [] as $l) if ((str_contains($l, ' install ') || str_contains($l, ' configure ')) && ($tf === '' || substr($l,0,10) >= $tf)) $ins[] = $l;
			$res['dpkg_log'] = ['count' => count($ins), 'lines' => array_slice($ins, -100)];
			foreach (array_slice($ins, -20) as $l) $ev[] = 'linux:dpkg:' . mb_substr($l, 0, 80);
		}

		$stem = basename(rtrim($root, '/')); $out = "{$case->derivedDir}/linux_artefacts_{$stem}.json"; $this->writeJson($out, $res);
		$summary = implode(', ', array_map(fn($k,$v) => "{$k}=" . (is_array($v) ? count($v) : '?'), array_keys($res), $res));
		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($res),
			producedFiles:     [$out],
			structuredResults: $res,
			evidencePointers:  array_slice($ev, 0, 60),
			stdoutExcerpt:     "Linux artefacts [{$stem}]: {$summary}",
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', "linux_artefact_parse {$stem}"),
		);
	}
}
