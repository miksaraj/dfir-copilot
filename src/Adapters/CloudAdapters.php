<?php

declare(strict_types=1);

namespace DFIRCopilot\Adapters;

use DFIRCopilot\Case\Workspace;
use DFIRCopilot\Config;
use DFIRCopilot\Executors\ExecResult;

// ─────────────────────────────────────────────────────────────────
// gzipped_log_parse
// ─────────────────────────────────────────────────────────────────

/**
 * Like log_parse, but transparently decompresses .gz / .log.gz files
 * before parsing. Also handles plain files for convenience.
 *
 * Relevant for: Nexus request logs, nexus audit logs, syslog rotations,
 * any tool that rotates logs with gzip compression.
 */
final class GzippedLogParse extends BaseAdapter
{
	public const NAME        = 'gzipped_log_parse';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Parse gzip-compressed log files (.gz, .log.gz) — or plain text logs — with keyword/regex filtering. Identical interface to log_parse but transparently decompresses before parsing. Essential for Nexus rotated logs, syslog.gz, and any gzip-rotated evidence.';
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
						'description' => 'Path to log file (relative to case dir). May be plain text or .gz compressed.',
					],
					'keywords' => [
						'type'        => 'array',
						'items'       => ['type' => 'string'],
						'description' => 'Return only lines containing any of these keywords (case-insensitive, OR logic).',
					],
					'regex' => [
						'type'        => 'string',
						'description' => 'Return only lines matching this regex (applied after keyword filter).',
					],
					'max_lines' => [
						'type'        => 'integer',
						'description' => 'Maximum matched lines to return (default: 300).',
						'default'     => 300,
					],
					'tail' => [
						'type'        => 'boolean',
						'description' => 'If true, return last N matched lines instead of first N.',
						'default'     => false,
					],
					'sort' => [
						'type'        => 'boolean',
						'description' => 'If true, sort matched lines alphabetically (useful for deduplication). Default false.',
						'default'     => false,
					],
				],
				'required' => ['file_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp       = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));
		$keywords = $params['keywords'] ?? [];
		$regex    = $params['regex'] ?? '';
		$maxLines = (int) ($params['max_lines'] ?? 300);
		$tail     = (bool) ($params['tail'] ?? false);
		$sort     = (bool) ($params['sort'] ?? false);

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		// Read lines — decompress if .gz
		$isGz = str_ends_with(strtolower($fp), '.gz');
		if ($isGz) {
			$gz = @gzopen($fp, 'rb');
			if ($gz === false) return $this->errorResult("Cannot open gzip file: {$fp}");
			$raw = '';
			while (!gzeof($gz)) {
				$raw .= gzread($gz, 65536);
			}
			gzclose($gz);
			$allLines = explode("\n", $raw);
		} else {
			$allLines = file($fp, FILE_IGNORE_NEW_LINES) ?: [];
		}

		$totalLines    = count($allLines);
		$keywordsLower = array_map('strtolower', $keywords);

		// Detect format from first non-empty line
		$format    = 'unknown';
		$firstLine = '';
		foreach ($allLines as $l) {
			if (trim($l) !== '') { $firstLine = $l; break; }
		}
		if (json_decode($firstLine) !== null)                                      $format = 'jsonl';
		elseif (str_contains($firstLine, ',') && substr_count($firstLine, ',') >= 2) $format = 'csv';
		elseif (preg_match('/^\d{4}-\d{2}-\d{2}/', $firstLine))                    $format = 'timestamped';
		elseif (preg_match('/^\d{2}\/\w{3}\/\d{4}:/', $firstLine))                 $format = 'clf'; // Combined Log Format (Nexus/Apache)
		elseif (preg_match('/^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}/', $firstLine)) $format = 'syslog';

		// Filter
		$matched = [];
		foreach ($allLines as $idx => $line) {
			if (trim($line) === '') continue;
			$lineno  = $idx + 1;
			$include = true;

			if (!empty($keywordsLower)) {
				$include = false;
				$lower   = strtolower($line);
				foreach ($keywordsLower as $kw) {
					if (str_contains($lower, $kw)) { $include = true; break; }
				}
			}

			if ($include && $regex !== '') {
				$include = (bool) @preg_match("/{$regex}/i", $line);
			}

			if ($include) {
				$matched[] = ['line' => $lineno, 'text' => $line];
			}
		}

		if ($sort) {
			usort($matched, fn($a, $b) => strcmp($a['text'], $b['text']));
		}

		if ($tail) {
			$matched = array_slice($matched, -$maxLines);
		} else {
			$matched = array_slice($matched, 0, $maxLines);
		}

		// Frequency analysis: IPs and HTTP methods (CLF pattern)
		$patterns = [];
		foreach ($allLines as $line) {
			if (preg_match('/\b(ERROR|WARN(?:ING)?|INFO|DEBUG|CRITICAL|FATAL)\b/i', $line, $m)) {
				$level = strtoupper($m[1]);
				$patterns['levels'][$level] = ($patterns['levels'][$level] ?? 0) + 1;
			}
			if (preg_match_all('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $line, $m)) {
				foreach ($m[0] as $ip) {
					$patterns['ips'][$ip] = ($patterns['ips'][$ip] ?? 0) + 1;
				}
			}
			// HTTP method hits (for CLF/Nexus)
			if (preg_match('/"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s/', $line, $m)) {
				$method = $m[1];
				$patterns['methods'][$method] = ($patterns['methods'][$method] ?? 0) + 1;
			}
		}

		if (isset($patterns['levels'])) arsort($patterns['levels']);
		if (isset($patterns['ips'])) {
			arsort($patterns['ips']);
			$patterns['ips'] = array_slice($patterns['ips'], 0, 20, true);
		}
		if (isset($patterns['methods'])) arsort($patterns['methods']);

		$stem    = pathinfo(str_replace('.gz', '', $fp), PATHINFO_FILENAME);
		$outPath = "{$case->derivedDir}/{$stem}_gzlog_parsed.json";
		$this->writeJson($outPath, [
			'source'   => basename($fp),
			'format'   => $format,
			'total'    => $totalLines,
			'matched'  => count($matched),
			'patterns' => $patterns,
			'lines'    => $matched,
		]);

		$evidence = [];
		foreach (array_slice($patterns['ips'] ?? [], 0, 5, true) as $ip => $cnt) {
			$evidence[] = "gzlog:{$stem}:ip={$ip}:count={$cnt}";
		}
		foreach ($patterns['methods'] ?? [] as $m => $cnt) {
			$evidence[] = "gzlog:{$stem}:method={$m}:count={$cnt}";
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: [
				'source'        => basename($fp),
				'format'        => $format,
				'compressed'    => $isGz,
				'total_lines'   => $totalLines,
				'matched_lines' => count($matched),
				'patterns'      => $patterns,
				'sample_lines'  => array_slice($matched, 0, 40),
			],
			evidencePointers:  $evidence,
			stdoutExcerpt:     "GzLog ({$format}" . ($isGz ? ', gz' : '') . "): {$totalLines} lines, " . count($matched) . " matched",
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', 'gzipped_log_parse ' . basename($fp)),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// cloudtrail_query
// ─────────────────────────────────────────────────────────────────

/**
 * Queries AWS CloudTrail logs stored as gzip-compressed JSON files in the
 * standard S3 export tree layout:
 *   cloudtrail/<region>/YYYY/MM/DD/<account>_CloudTrail_<region>_<ts>.json.gz
 *
 * Filters by any combination of: source IP, access key ID, event name,
 * AWS service (eventSource), error code (or success-only).
 * Searches across multiple regions and date ranges efficiently.
 *
 * Relevant for: IAM credential abuse, lateral movement, data exfiltration
 * via AWS APIs, CloudTrail-based intrusion investigations.
 */
final class CloudTrailQuery extends BaseAdapter
{
	public const NAME        = 'cloudtrail_query';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Query AWS CloudTrail logs (gzip-compressed JSON, standard S3 export layout) across multiple regions and dates. Filter by source IP, access key ID, event name, AWS service, or error code. Returns matching events sorted by time. Essential for cloud intrusion investigations involving stolen IAM credentials.';
	public const TARGET      = 'local';

	/** How many events to return at most. */
	private const MAX_EVENTS = 500;

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'trail_dir' => [
						'type'        => 'string',
						'description' => 'Path to the root CloudTrail directory (relative to case dir). E.g. "raw/evidence/AWS/cloudtrail". All .json.gz files beneath this path are searched.',
					],
					'source_ip' => [
						'type'        => 'string',
						'description' => 'Filter: only return events from this source IP address.',
					],
					'access_key_id' => [
						'type'        => 'string',
						'description' => 'Filter: only return events using this IAM access key ID.',
					],
					'event_name' => [
						'type'        => 'string',
						'description' => 'Filter: only return events with this eventName (case-insensitive substring match — e.g. "ListObjects" matches "ListObjectsV2").',
					],
					'event_source' => [
						'type'        => 'string',
						'description' => 'Filter: only return events from this AWS service source (e.g. "s3", "lambda", "iam"). Substring match.',
					],
					'exclude_ips' => [
						'type'        => 'array',
						'items'       => ['type' => 'string'],
						'description' => 'Exclude events from these IP addresses (e.g. known-good builder IPs).',
					],
					'success_only' => [
						'type'        => 'boolean',
						'description' => 'If true, only return events with no errorCode (successful API calls). Default false.',
						'default'     => false,
					],
					'errors_only' => [
						'type'        => 'boolean',
						'description' => 'If true, only return events that have an errorCode (failed calls). Default false.',
						'default'     => false,
					],
					'regions' => [
						'type'        => 'array',
						'items'       => ['type' => 'string'],
						'description' => 'Restrict search to these AWS regions (e.g. ["eu-north-1", "us-east-1"]). Searches all regions if omitted.',
					],
					'date_from' => [
						'type'        => 'string',
						'description' => 'Start date filter in YYYY-MM-DD format. Inclusive.',
					],
					'date_to' => [
						'type'        => 'string',
						'description' => 'End date filter in YYYY-MM-DD format. Inclusive.',
					],
					'max_events' => [
						'type'        => 'integer',
						'description' => 'Maximum events to return (default: 200, max: 500).',
						'default'     => 200,
					],
				],
				'required' => ['trail_dir'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$trailRel   = $this->requireParam($params, 'trail_dir');
		$trailAbs   = $this->resolveFilePath($case, $trailRel);
		$sourceIp   = $params['source_ip'] ?? '';
		$accessKey  = $params['access_key_id'] ?? '';
		$eventName  = strtolower($params['event_name'] ?? '');
		$eventSrc   = strtolower($params['event_source'] ?? '');
		$excludeIps = $params['exclude_ips'] ?? [];
		$successOnly = (bool) ($params['success_only'] ?? false);
		$errorsOnly  = (bool) ($params['errors_only'] ?? false);
		$regions    = $params['regions'] ?? [];
		$dateFrom   = $params['date_from'] ?? '';
		$dateTo     = $params['date_to'] ?? '';
		$maxEvents  = min((int) ($params['max_events'] ?? 200), self::MAX_EVENTS);

		if (!is_dir($trailAbs)) {
			return $this->errorResult("CloudTrail directory not found: {$trailRel}");
		}

		// Enumerate all .json.gz files
		$iter  = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator($trailAbs, \FilesystemIterator::SKIP_DOTS),
			\RecursiveIteratorIterator::LEAVES_ONLY
		);

		$files = [];
		foreach ($iter as $file) {
			/** @var \SplFileInfo $file */
			if (!str_ends_with(strtolower($file->getFilename()), '.json.gz')) continue;

			$path = $file->getPathname();

			// Region filter (directory segment)
			if (!empty($regions)) {
				$skip = true;
				foreach ($regions as $r) {
					if (str_contains($path, "/{$r}/")) { $skip = false; break; }
				}
				if ($skip) continue;
			}

			// Date filter: derive YYYY/MM/DD from path
			if ($dateFrom !== '' || $dateTo !== '') {
				if (preg_match('#/(\d{4})/(\d{2})/(\d{2})/#', $path, $m)) {
					$fileDate = "{$m[1]}-{$m[2]}-{$m[3]}";
					if ($dateFrom !== '' && $fileDate < $dateFrom) continue;
					if ($dateTo   !== '' && $fileDate > $dateTo)   continue;
				}
			}

			$files[] = $path;
		}

		sort($files);

		$events      = [];
		$filesScanned = 0;
		$totalRecords = 0;

		foreach ($files as $gz) {
			$handle = @gzopen($gz, 'rb');
			if ($handle === false) continue;

			$raw = '';
			while (!gzeof($handle)) {
				$raw .= gzread($handle, 65536);
			}
			gzclose($handle);

			$data = json_decode($raw, true);
			if (!is_array($data) || !isset($data['Records'])) continue;

			$filesScanned++;
			$totalRecords += count($data['Records']);

			foreach ($data['Records'] as $e) {
				// Source IP filter
				if ($sourceIp !== '' && ($e['sourceIPAddress'] ?? '') !== $sourceIp) continue;

				// Exclude IPs
				if (!empty($excludeIps) && in_array($e['sourceIPAddress'] ?? '', $excludeIps, true)) continue;

				// Access key filter
				if ($accessKey !== '') {
					$ak = $e['userIdentity']['accessKeyId'] ?? '';
					if ($ak !== $accessKey) continue;
				}

				// Event name filter (substring)
				if ($eventName !== '' && !str_contains(strtolower($e['eventName'] ?? ''), $eventName)) continue;

				// Event source filter
				if ($eventSrc !== '' && !str_contains(strtolower($e['eventSource'] ?? ''), $eventSrc)) continue;

				// Error code filters
				$hasError = isset($e['errorCode']) && $e['errorCode'] !== '';
				if ($successOnly && $hasError) continue;
				if ($errorsOnly && !$hasError) continue;

				$events[] = [
					'eventTime'    => $e['eventTime'] ?? '',
					'eventName'    => $e['eventName'] ?? '',
					'eventSource'  => $e['eventSource'] ?? '',
					'awsRegion'    => $e['awsRegion'] ?? '',
					'sourceIPAddress' => $e['sourceIPAddress'] ?? '',
					'userArn'      => $e['userIdentity']['arn'] ?? '',
					'accessKeyId'  => $e['userIdentity']['accessKeyId'] ?? '',
					'errorCode'    => $e['errorCode'] ?? null,
					'errorMessage' => $e['errorMessage'] ?? null,
					'requestParameters' => $e['requestParameters'] ?? null,
				];

				if (count($events) >= $maxEvents * 3) break; // collect extra for dedup before truncating
			}
		}

		// Sort by eventTime, deduplicate, then truncate
		usort($events, fn($a, $b) => strcmp($a['eventTime'], $b['eventTime']));
		$events = array_slice($events, 0, $maxEvents);

		// Build unique IP/key/event name summaries
		$uniqueIps    = array_unique(array_column($events, 'sourceIPAddress'));
		$uniqueKeys   = array_unique(array_filter(array_column($events, 'accessKeyId')));
		$uniqueEvents = array_count_values(array_column($events, 'eventName'));
		arsort($uniqueEvents);

		$outPath = "{$case->derivedDir}/cloudtrail_query_" . time() . '.json';
		$this->writeJson($outPath, [
			'query'   => array_filter(compact('sourceIp', 'accessKey', 'eventName', 'eventSrc', 'dateFrom', 'dateTo', 'regions')),
			'stats'   => [
				'files_scanned'  => $filesScanned,
				'total_records'  => $totalRecords,
				'matched_events' => count($events),
			],
			'summary' => [
				'unique_source_ips'  => array_values($uniqueIps),
				'unique_access_keys' => array_values($uniqueKeys),
				'event_name_counts'  => $uniqueEvents,
			],
			'events'  => $events,
		]);

		$evidence = [];
		foreach (array_slice($uniqueIps, 0, 5) as $ip) {
			$evidence[] = "cloudtrail:ip={$ip}";
		}
		foreach (array_slice(array_keys($uniqueEvents), 0, 5) as $ev) {
			$evidence[] = "cloudtrail:event={$ev}";
		}

		$summary = sprintf(
			"CloudTrail: %d files, %d records → %d matched events",
			$filesScanned, $totalRecords, count($events)
		);
		if ($sourceIp)  $summary .= " [ip={$sourceIp}]";
		if ($accessKey) $summary .= " [key=...{$accessKey}]";

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: [
				'files_scanned'  => $filesScanned,
				'total_records'  => $totalRecords,
				'matched_events' => count($events),
				'unique_ips'     => array_values($uniqueIps),
				'unique_keys'    => array_values($uniqueKeys),
				'event_counts'   => array_slice($uniqueEvents, 0, 20, true),
				'events'         => array_slice($events, 0, 40),
			],
			evidencePointers:  $evidence,
			stdoutExcerpt:     $summary,
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', 'cloudtrail_query'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// gh_security_log
// ─────────────────────────────────────────────────────────────────

/**
 * Parses a GitHub organisation/user Security Audit Log exported as JSON.
 *
 * GitHub audit events use epoch-millisecond timestamps (@timestamp),
 * actor/actor_ip instead of "user"/"sourceIP", and action strings like
 * "user.login", "user.two_factor_challenge_failure", "repo.push", etc.
 *
 * This adapter converts epoch-ms to ISO-8601, lets the analyst filter by
 * action, actor, IP, or time range, and flags high-risk events automatically.
 *
 * Relevant for: account takeover via GitHub, CI/CD supply-chain attacks,
 * OAuth token theft, repository push/secret-access events.
 */
final class GhSecurityLog extends BaseAdapter
{
	public const NAME        = 'gh_security_log';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Parse a GitHub Security Audit Log JSON export. Converts epoch-ms timestamps, filters by action/actor/IP/time-range, and auto-flags high-risk events (account takeover, MFA bypass, unrecognized device). Essential for GitHub-based supply-chain and CI/CD compromise investigations.';
	public const TARGET      = 'local';

	/** Actions that warrant a high-risk flag */
	private const HIGH_RISK_ACTIONS = [
		'user.login',
		'user.sign_in_from_unrecognized_device_and_location',
		'user.two_factor_challenge_failure',
		'user.two_factor_challenge_success',
		'user.failed_login',
		'user.password_reset_request',
		'oauth_access.create',
		'repo.destroy',
		'org.invite_member',
		'team.add_member',
		'protected_branch.policy_override',
		'secret_scanning_alert.reopen',
	];

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
						'description' => 'Path to the GitHub Security Log JSON file (relative to case dir). Must be a JSON array of audit event objects.',
					],
					'action_filter' => [
						'type'        => 'string',
						'description' => 'Filter: only return events whose action contains this string (case-insensitive). E.g. "login", "push", "oauth".',
					],
					'actor_filter' => [
						'type'        => 'string',
						'description' => 'Filter: only return events by this GitHub actor/username.',
					],
					'ip_filter' => [
						'type'        => 'string',
						'description' => 'Filter: only return events from this source IP address.',
					],
					'time_from' => [
						'type'        => 'string',
						'description' => 'Start time filter in ISO-8601 or YYYY-MM-DD format. Inclusive.',
					],
					'time_to' => [
						'type'        => 'string',
						'description' => 'End time filter in ISO-8601 or YYYY-MM-DD format. Inclusive.',
					],
					'high_risk_only' => [
						'type'        => 'boolean',
						'description' => 'If true, only return pre-identified high-risk events (logins, MFA bypass, OAuth token creation, etc). Default false.',
						'default'     => false,
					],
					'max_events' => [
						'type'        => 'integer',
						'description' => 'Maximum events to return (default: 200).',
						'default'     => 200,
					],
				],
				'required' => ['file_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp           = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));
		$actionFilter = strtolower($params['action_filter'] ?? '');
		$actorFilter  = strtolower($params['actor_filter'] ?? '');
		$ipFilter     = $params['ip_filter'] ?? '';
		$timeFrom     = $params['time_from'] ?? '';
		$timeTo       = $params['time_to'] ?? '';
		$highRiskOnly = (bool) ($params['high_risk_only'] ?? false);
		$maxEvents    = (int) ($params['max_events'] ?? 200);

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$raw = file_get_contents($fp);
		if ($raw === false) return $this->errorResult("Cannot read file: {$fp}");

		$data = json_decode($raw, true);
		if (!is_array($data)) return $this->errorResult("File is not valid JSON: {$fp}");

		// Normalise: handle both top-level array and {"Records":[...]} / {"events":[...]}
		if (isset($data['Records']))     $data = $data['Records'];
		elseif (isset($data['events']))  $data = $data['events'];

		// Convert numeric timestamps and filter
		$tsFrom = $timeFrom !== '' ? strtotime($timeFrom) * 1000 : 0;
		$tsTo   = $timeTo   !== '' ? strtotime($timeTo . ' 23:59:59') * 1000 : PHP_INT_MAX;

		$matched    = [];
		$allActions = [];

		foreach ($data as $ev) {
			$tsMs   = (int) ($ev['@timestamp'] ?? $ev['timestamp'] ?? 0);
			$action = $ev['action'] ?? '';
			$actor  = strtolower($ev['actor'] ?? $ev['user'] ?? '');
			$ip     = $ev['actor_ip'] ?? $ev['ip'] ?? '';

			$allActions[$action] = ($allActions[$action] ?? 0) + 1;

			// Time range
			if ($tsMs < $tsFrom || $tsMs > $tsTo) continue;

			// Action filter
			if ($actionFilter !== '' && !str_contains(strtolower($action), $actionFilter)) continue;

			// Actor filter
			if ($actorFilter !== '' && $actor !== strtolower($actorFilter)) continue;

			// IP filter
			if ($ipFilter !== '' && $ip !== $ipFilter) continue;

			// High-risk filter
			$isHighRisk = in_array($action, self::HIGH_RISK_ACTIONS, true);
			if ($highRiskOnly && !$isHighRisk) continue;

			$isoTime = $tsMs > 0
				? (new \DateTime('@' . intdiv($tsMs, 1000)))->format('Y-m-d\TH:i:s.') . str_pad((string)($tsMs % 1000), 3, '0', STR_PAD_LEFT) . 'Z'
				: '';

			$matched[] = [
				'timestamp'  => $isoTime,
				'timestamp_ms' => $tsMs,
				'action'     => $action,
				'actor'      => $ev['actor'] ?? $ev['user'] ?? '',
				'actor_ip'   => $ip,
				'country_code' => $ev['country_code'] ?? '',
				'user_agent' => $ev['user_agent'] ?? '',
				'repo'       => $ev['repo'] ?? '',
				'high_risk'  => $isHighRisk,
				'raw'        => $ev,
			];
		}

		// Sort chronologically
		usort($matched, fn($a, $b) => $a['timestamp_ms'] <=> $b['timestamp_ms']);
		$matched = array_slice($matched, 0, $maxEvents);

		// Summaries
		arsort($allActions);
		$uniqueIps    = array_unique(array_filter(array_column($matched, 'actor_ip')));
		$uniqueActors = array_unique(array_filter(array_column($matched, 'actor')));
		$highRiskEvs  = array_filter($matched, fn($e) => $e['high_risk']);

		$stem    = pathinfo($fp, PATHINFO_FILENAME);
		$outPath = "{$case->derivedDir}/{$stem}_gh_security.json";
		$this->writeJson($outPath, [
			'total_events'   => count($data),
			'matched_events' => count($matched),
			'action_counts'  => $allActions,
			'high_risk'      => array_values($highRiskEvs),
			'events'         => $matched,
		]);

		$evidence = [];
		foreach (array_slice($uniqueIps, 0, 5) as $ip) {
			$evidence[] = "gh_security:ip={$ip}";
		}
		foreach (array_slice($uniqueActors, 0, 5) as $actor) {
			$evidence[] = "gh_security:actor={$actor}";
		}
		if (!empty($highRiskEvs)) {
			$evidence[] = "gh_security:high_risk_events=" . count($highRiskEvs);
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: [
				'total_events'   => count($data),
				'matched_events' => count($matched),
				'unique_ips'     => array_values($uniqueIps),
				'unique_actors'  => array_values($uniqueActors),
				'high_risk_count' => count($highRiskEvs),
				'action_counts'  => array_slice($allActions, 0, 20, true),
				'high_risk_events' => array_values(array_slice($highRiskEvs, 0, 10)),
				'events'         => array_slice($matched, 0, 40),
			],
			evidencePointers:  $evidence,
			stdoutExcerpt:     "GH Security Log: " . count($data) . " total → " . count($matched) . " matched, " . count($highRiskEvs) . " high-risk",
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', 'gh_security_log ' . basename($fp)),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// s3_access_log_query
// ─────────────────────────────────────────────────────────────────

/**
 * Queries a directory of S3/ObjectVault server access log files in bulk.
 *
 * S3 access logs use a fixed space-delimited format (AWS Combined Log Format):
 *   bucket-owner bucket [datetime] ip requesterId requestId operation key
 *   "request-uri" status errorCode bytesSent objectSize totalTime ... userAgent ...
 *
 * Relevant for: S3 data exfiltration, ObjectVault access investigation,
 * attacker IP enumeration, PUT/GET of specific keys, user-agent fingerprinting.
 */
final class S3AccessLogQuery extends BaseAdapter
{
	public const NAME        = 's3_access_log_query';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Query a directory of S3 / ObjectVault server access log files in bulk. Filters across all files by source IP, HTTP method (GET/PUT/DELETE etc.), object key prefix, HTTP status code, or operation type. Returns parsed structured entries with bucket, key, user-agent, status, and bytes. Eliminates the need to run log_parse on each file individually.';
	public const TARGET      = 'local';

	/** S3 access log field positions (0-indexed, space-split with quoted fields handled) */
	private const F_BUCKET    = 1;
	private const F_DATETIME  = 2; // [dd/Mon/YYYY:HH:MM:SS +0000]
	private const F_IP        = 4;
	private const F_OPERATION = 7;
	private const F_KEY       = 8;
	private const F_REQUEST   = 9; // "METHOD /path HTTP/x"
	private const F_STATUS    = 10;
	private const F_ERROR     = 11;
	private const F_BYTES     = 12;
	private const F_UA        = 19; // approximate; may shift with extended fields

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
						'description' => 'Path to the directory containing S3 access log files (relative to case dir). All files in this directory are scanned (non-recursive by default).',
					],
					'source_ip' => [
						'type'        => 'string',
						'description' => 'Filter: only return entries from this source IP.',
					],
					'method' => [
						'type'        => 'string',
						'description' => 'Filter: HTTP method to match (e.g. "PUT", "GET", "DELETE"). Case-insensitive.',
					],
					'operation' => [
						'type'        => 'string',
						'description' => 'Filter: S3 operation to match (e.g. "REST.PUT.OBJECT", "REST.GET.OBJECT"). Substring match.',
					],
					'key_prefix' => [
						'type'        => 'string',
						'description' => 'Filter: only return entries where the object key starts with this prefix.',
					],
					'status_code' => [
						'type'        => 'integer',
						'description' => 'Filter: only return entries with this HTTP status code (e.g. 200, 403, 404).',
					],
					'exclude_ips' => [
						'type'        => 'array',
						'items'       => ['type' => 'string'],
						'description' => 'Exclude entries from these IP addresses (e.g. known CDN edge IPs).',
					],
					'max_entries' => [
						'type'        => 'integer',
						'description' => 'Maximum entries to return (default: 300).',
						'default'     => 300,
					],
					'recursive' => [
						'type'        => 'boolean',
						'description' => 'If true, search log files recursively in subdirectories. Default false.',
						'default'     => false,
					],
				],
				'required' => ['log_dir'],
			],
		];
	}

	/** Parse one S3 access log line into an array of fields, handling quoted segments. */
	private function parseLine(string $line): array
	{
		$fields = [];
		$len    = strlen($line);
		$i      = 0;

		while ($i < $len) {
			// Skip leading spaces
			while ($i < $len && $line[$i] === ' ') $i++;
			if ($i >= $len) break;

			if ($line[$i] === '"') {
				// Quoted field
				$i++;
				$start = $i;
				while ($i < $len && $line[$i] !== '"') $i++;
				$fields[] = substr($line, $start, $i - $start);
				$i++; // skip closing "
			} elseif ($line[$i] === '[') {
				// Bracketed field (datetime)
				$i++;
				$start = $i;
				while ($i < $len && $line[$i] !== ']') $i++;
				$fields[] = substr($line, $start, $i - $start);
				$i++; // skip ]
			} else {
				$start = $i;
				while ($i < $len && $line[$i] !== ' ') $i++;
				$fields[] = substr($line, $start, $i - $start);
			}
		}

		return $fields;
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$logRel     = $this->requireParam($params, 'log_dir');
		$logAbs     = $this->resolveFilePath($case, $logRel);
		$sourceIp   = $params['source_ip'] ?? '';
		$method     = strtoupper($params['method'] ?? '');
		$operation  = strtoupper($params['operation'] ?? '');
		$keyPrefix  = $params['key_prefix'] ?? '';
		$statusCode = isset($params['status_code']) ? (int) $params['status_code'] : null;
		$excludeIps = $params['exclude_ips'] ?? [];
		$maxEntries = (int) ($params['max_entries'] ?? 300);
		$recursive  = (bool) ($params['recursive'] ?? false);

		if (!is_dir($logAbs)) {
			return $this->errorResult("Log directory not found: {$logRel}");
		}

		// Enumerate files
		$files = [];
		if ($recursive) {
			$iter = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator($logAbs, \FilesystemIterator::SKIP_DOTS),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ($iter as $f) {
				/** @var \SplFileInfo $f */
				if ($f->isFile()) $files[] = $f->getPathname();
			}
		} else {
			foreach (scandir($logAbs) ?: [] as $fn) {
				if ($fn === '.' || $fn === '..') continue;
				$full = "{$logAbs}/{$fn}";
				if (is_file($full)) $files[] = $full;
			}
		}
		sort($files);

		$entries     = [];
		$filesScanned = 0;
		$totalLines  = 0;
		$ipCounts    = [];
		$opCounts    = [];
		$statusCounts = [];

		foreach ($files as $file) {
			$lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			if ($lines === false) continue;
			$filesScanned++;

			foreach ($lines as $line) {
				$totalLines++;
				$f = $this->parseLine($line);
				if (count($f) < 12) continue;

				$entryIp  = $f[self::F_IP]        ?? '-';
				$entryOp  = $f[self::F_OPERATION]  ?? '-';
				$entryKey = $f[self::F_KEY]        ?? '-';
				$entryReq = $f[self::F_REQUEST]    ?? '-';
				$entrySt  = (int) ($f[self::F_STATUS] ?? 0);
				$entryUa  = $f[self::F_UA]         ?? '-';
				$entryDt  = $f[self::F_DATETIME]   ?? '-';
				$entryBytes = $f[self::F_BYTES]    ?? '-';

				// Derive method from request string "GET /key HTTP/1.1"
				$entryMethod = strtoupper(explode(' ', $entryReq)[0] ?? '');

				// Aggregates
				$ipCounts[$entryIp]       = ($ipCounts[$entryIp] ?? 0) + 1;
				$opCounts[$entryOp]       = ($opCounts[$entryOp] ?? 0) + 1;
				$statusCounts[$entrySt]   = ($statusCounts[$entrySt] ?? 0) + 1;

				// Filters
				if ($sourceIp !== '' && $entryIp !== $sourceIp) continue;
				if (!empty($excludeIps) && in_array($entryIp, $excludeIps, true)) continue;
				if ($method !== '' && $entryMethod !== $method) continue;
				if ($operation !== '' && !str_contains($entryOp, $operation)) continue;
				if ($keyPrefix !== '' && !str_starts_with($entryKey, $keyPrefix)) continue;
				if ($statusCode !== null && $entrySt !== $statusCode) continue;

				$entries[] = [
					'datetime'   => $entryDt,
					'ip'         => $entryIp,
					'operation'  => $entryOp,
					'key'        => $entryKey,
					'method'     => $entryMethod,
					'status'     => $entrySt,
					'bytes'      => $entryBytes,
					'user_agent' => $entryUa,
					'source_file' => basename($file),
				];

				if (count($entries) >= $maxEntries * 2) break;
			}
		}

		$entries = array_slice($entries, 0, $maxEntries);

		arsort($ipCounts);
		arsort($opCounts);
		arsort($statusCounts);

		// Unique user agents from matched entries
		$uniqueUAs = array_unique(array_filter(array_column($entries, 'user_agent'), fn($ua) => $ua !== '-'));

		$outPath = "{$case->derivedDir}/s3_access_log_query_" . time() . '.json';
		$this->writeJson($outPath, [
			'query'   => array_filter(compact('sourceIp', 'method', 'operation', 'keyPrefix', 'statusCode')),
			'stats'   => [
				'files_scanned'   => $filesScanned,
				'total_lines'     => $totalLines,
				'matched_entries' => count($entries),
			],
			'summary' => [
				'top_source_ips'  => array_slice($ipCounts, 0, 10, true),
				'operation_counts' => array_slice($opCounts, 0, 10, true),
				'status_counts'   => $statusCounts,
				'unique_user_agents' => array_values($uniqueUAs),
			],
			'entries' => $entries,
		]);

		$evidence = [];
		foreach (array_slice(array_keys($ipCounts), 0, 5) as $ip) {
			$evidence[] = "s3_access:ip={$ip}:count={$ipCounts[$ip]}";
		}
		foreach (array_values($uniqueUAs) as $ua) {
			$evidence[] = "s3_access:ua=" . substr($ua, 0, 80);
		}

		$summary = "S3 Access Logs: {$filesScanned} files, {$totalLines} lines → " . count($entries) . " matched";
		if ($sourceIp)   $summary .= " [ip={$sourceIp}]";
		if ($method)     $summary .= " [method={$method}]";
		if ($statusCode) $summary .= " [status={$statusCode}]";

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: [
				'files_scanned'      => $filesScanned,
				'total_lines'        => $totalLines,
				'matched_entries'    => count($entries),
				'top_source_ips'     => array_slice($ipCounts, 0, 10, true),
				'operation_counts'   => array_slice($opCounts, 0, 10, true),
				'status_counts'      => $statusCounts,
				'unique_user_agents' => array_values($uniqueUAs),
				'entries'            => array_slice($entries, 0, 40),
			],
			evidencePointers:  $evidence,
			stdoutExcerpt:     $summary,
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', 's3_access_log_query'),
		);
	}
}
