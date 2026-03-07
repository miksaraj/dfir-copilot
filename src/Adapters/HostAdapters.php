<?php

declare(strict_types=1);

namespace DFIRCopilot\Adapters;

use DFIRCopilot\Case\Workspace;
use DFIRCopilot\Config;
use DFIRCopilot\Executors\ExecResult;
use DFIRCopilot\Executors\LocalExecutor;

// ─────────────────────────────────────────────────────────────────
// intake_bundle
// ─────────────────────────────────────────────────────────────────

final class IntakeBundle extends BaseAdapter
{
	public const NAME        = 'intake_bundle';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Ingest a challenge bundle into the case. Computes hashes, preserves structure, produces inventory.';
	public const TARGET      = 'local';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'bundle_path' => [
						'type'        => 'string',
						'description' => 'Path to the challenge bundle (file or directory)',
					],
				],
				'required' => ['bundle_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$bundlePath = $this->requireParam($params, 'bundle_path');
		$inventory  = $case->ingestBundle($bundlePath);
		$count      = count($inventory['files']);

		$evidence = [];
		foreach ($inventory['files'] as $i => $f) {
			$name = $f['relative_path'] ?? $f['stored_as'] ?? '?';
			$evidence[] = "inventory:{$i}:{$name}";
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$case->inventoryPath],
			structuredResults: $inventory,
			evidencePointers:  $evidence,
			stdoutExcerpt:     "Ingested {$count} files",
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', 'intake_bundle'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// file_id
// ─────────────────────────────────────────────────────────────────

final class FileID extends BaseAdapter
{
	public const NAME        = 'file_id';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Identify file type, compute hashes, measure entropy. Works on any single file.';
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
						'description' => 'Path to the file (relative to case dir)',
					],
				],
				'required' => ['file_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));

		if (!file_exists($fp)) {
			return $this->errorResult("File not found: {$fp}");
		}

		$results = [];

		// file magic (via `file` command)
		$exec = new LocalExecutor();
		$r = $exec->run(['file', '-b', $fp]);
		$results['magic'] = trim($r->stdout);

		// Hashes
		$results['sha256']     = hash_file('sha256', $fp);
		$results['md5']        = hash_file('md5', $fp);
		$results['size_bytes'] = filesize($fp);

		// Entropy
		$data = file_get_contents($fp);
		if ($data !== false && strlen($data) > 0) {
			$results['entropy'] = round($this->shannonEntropy($data), 4);
		}

		// PE / ELF detection
		if (strlen($data) >= 4) {
			$results['is_pe']  = str_starts_with($data, "MZ");
			$results['is_elf'] = str_starts_with($data, "\x7fELF");
		}

		// Save
		$stem    = pathinfo($fp, PATHINFO_FILENAME);
		$outPath = "{$case->derivedDir}/file_id_{$stem}.json";
		$this->writeJson($outPath, $results);

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: $results,
			evidencePointers:  [
								   "file_id:" . basename($fp) . ":magic={$results['magic']}",
								   "file_id:" . basename($fp) . ":sha256={$results['sha256']}",
								   "file_id:" . basename($fp) . ":entropy=" . ($results['entropy'] ?? '?'),
							   ],
			stdoutExcerpt:     json_encode($results, JSON_PRETTY_PRINT),
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', "file_id " . basename($fp)),
		);
	}

	private function shannonEntropy(string $data): float
	{
		$len  = strlen($data);
		$freq = array_count_values(str_split($data));
		$ent  = 0.0;

		foreach ($freq as $count) {
			$p = $count / $len;
			$ent -= $p * log($p, 2);
		}

		return $ent;
	}
}

// ─────────────────────────────────────────────────────────────────
// extract_iocs
// ─────────────────────────────────────────────────────────────────

final class ExtractIOCs extends BaseAdapter
{
	public const NAME        = 'extract_iocs';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Extract IOCs (IPs, domains, URLs, emails, hashes) from a text file with line numbers.';
	public const TARGET      = 'local';

	private const IP_RE     = '/\b(?:\d{1,3}\.){3}\d{1,3}\b/';
	private const URL_RE    = '#https?://[^\s<>"\']+#i';
	private const DOMAIN_RE = '/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk|ml|ga|cf|pw|gov|mil|edu|co|uk|de|fr|jp|kr|br|in|au|za|nl|se|no|fi|dk|onion|bit)\b/i';
	private const EMAIL_RE  = '/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/';
	private const MD5_RE    = '/\b[a-fA-F0-9]{32}\b/';
	private const SHA1_RE   = '/\b[a-fA-F0-9]{40}\b/';
	private const SHA256_RE = '/\b[a-fA-F0-9]{64}\b/';

	private const NOISE_DOMAINS = [
		'microsoft.com', 'windows.com', 'google.com', 'mozilla.org',
		'w3.org', 'xml.org', 'schemas.microsoft.com', 'openxml.org',
		'example.com', 'localhost',
	];

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'input_file' => [
						'type'        => 'string',
						'description' => 'Path to text file to scan for IOCs',
					],
				],
				'required' => ['input_file'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp = $this->resolveFilePath($case, $this->requireParam($params, 'input_file'));

		if (!file_exists($fp)) {
			return $this->errorResult("File not found: {$fp}");
		}

		$iocs = [
			'ips' => [], 'domains' => [], 'urls' => [], 'emails' => [],
			'md5s' => [], 'sha1s' => [], 'sha256s' => [],
		];
		$evidence = [];
		$seen     = [];

		$lines = file($fp, FILE_IGNORE_NEW_LINES);

		foreach ($lines as $idx => $line) {
			$lineno = $idx + 1;

			// IPs
			if (preg_match_all(self::IP_RE, $line, $m)) {
				foreach ($m[0] as $ip) {
					$parts = explode('.', $ip);
					$valid = true;
					foreach ($parts as $p) {
						if ((int) $p > 255) { $valid = false; break; }
					}
					if ($valid && !str_starts_with($ip, '0.') && !str_starts_with($ip, '127.') && !str_starts_with($ip, '255.')) {
						if (!isset($seen["ip:{$ip}"])) {
							$seen["ip:{$ip}"] = true;
							$iocs['ips'][] = ['value' => $ip, 'line' => $lineno, 'context' => mb_substr(trim($line), 0, 120)];
							$evidence[]    = "ioc:ip:{$ip}:line={$lineno}";
						}
					}
				}
			}

			// URLs
			if (preg_match_all(self::URL_RE, $line, $m)) {
				foreach ($m[0] as $url) {
					if (!isset($seen["url:{$url}"])) {
						$seen["url:{$url}"] = true;
						$iocs['urls'][]  = ['value' => $url, 'line' => $lineno, 'context' => mb_substr(trim($line), 0, 120)];
						$evidence[]      = "ioc:url:" . mb_substr($url, 0, 80) . ":line={$lineno}";
					}
				}
			}

			// Domains
			if (preg_match_all(self::DOMAIN_RE, $line, $m)) {
				foreach ($m[0] as $dom) {
					$domLower = strtolower($dom);
					if (!in_array($domLower, self::NOISE_DOMAINS, true) && !isset($seen["dom:{$domLower}"])) {
						$seen["dom:{$domLower}"] = true;
						$iocs['domains'][] = ['value' => $dom, 'line' => $lineno, 'context' => mb_substr(trim($line), 0, 120)];
						$evidence[]        = "ioc:domain:{$dom}:line={$lineno}";
					}
				}
			}

			// Emails
			if (preg_match_all(self::EMAIL_RE, $line, $m)) {
				foreach ($m[0] as $email) {
					if (!isset($seen["email:{$email}"])) {
						$seen["email:{$email}"] = true;
						$iocs['emails'][] = ['value' => $email, 'line' => $lineno];
					}
				}
			}

			// Hashes (sha256 > sha1 > md5 priority to avoid substrings)
			if (preg_match_all(self::SHA256_RE, $line, $m)) {
				foreach ($m[0] as $h) {
					if (!isset($seen["hash:{$h}"])) {
						$seen["hash:{$h}"] = true;
						$iocs['sha256s'][] = ['value' => $h, 'line' => $lineno];
					}
				}
			}
			if (preg_match_all(self::SHA1_RE, $line, $m)) {
				foreach ($m[0] as $h) {
					if (!isset($seen["hash:{$h}"])) {
						$seen["hash:{$h}"] = true;
						$iocs['sha1s'][] = ['value' => $h, 'line' => $lineno];
					}
				}
			}
			if (preg_match_all(self::MD5_RE, $line, $m)) {
				foreach ($m[0] as $h) {
					if (!isset($seen["hash:{$h}"])) {
						$seen["hash:{$h}"] = true;
						$iocs['md5s'][] = ['value' => $h, 'line' => $lineno];
					}
				}
			}
		}

		$summary = array_map(fn(array $v) => count($v), $iocs);

		$stem    = pathinfo($fp, PATHINFO_FILENAME);
		$outPath = "{$case->iocsDir}/iocs_{$stem}.json";
		$this->writeJson($outPath, $iocs);

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: ['summary' => $summary, 'iocs' => $iocs],
			evidencePointers:  array_slice($evidence, 0, 100),
			stdoutExcerpt:     "Extracted IOCs: " . json_encode($summary),
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', "extract_iocs " . basename($fp)),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// attack_map
// ─────────────────────────────────────────────────────────────────

final class ATTACKMap extends BaseAdapter
{
	public const NAME        = 'attack_map';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Map observed behaviors/artifacts to MITRE ATT&CK techniques. Input: list of observation strings.';
	public const TARGET      = 'local';

	private const PATTERNS = [
		'scheduled task|schtasks'                        => ['T1053.005', 'Scheduled Task/Job: Scheduled Task'],
		'registry.*run|autorun|HKLM.*Run'                => ['T1547.001', 'Boot or Logon Autostart: Registry Run Keys'],
		'powershell|pwsh|\.ps1'                          => ['T1059.001', 'Command and Scripting Interpreter: PowerShell'],
		'cmd\.exe|cmd /c'                                => ['T1059.003', 'Command and Scripting Interpreter: Windows Command Shell'],
		'wmi|wmic'                                       => ['T1047', 'Windows Management Instrumentation'],
		'certutil.*decode|certutil.*urlcache'            => ['T1140', 'Deobfuscate/Decode Files or Information'],
		'base64|obfuscat'                                => ['T1027', 'Obfuscated Files or Information'],
		'dll.*inject|inject.*dll|createremotethread'     => ['T1055.001', 'Process Injection: DLL Injection'],
		'process.*hollow'                                => ['T1055.012', 'Process Injection: Process Hollowing'],
		'mimikatz|lsass|credential.*dump'                => ['T1003.001', 'OS Credential Dumping: LSASS Memory'],
		'pass.*the.*hash|pth'                            => ['T1550.002', 'Use Alternate Authentication Material: Pass the Hash'],
		'lateral.*move|psexec|wmiexec'                   => ['T1021', 'Remote Services'],
		'exfiltrat|data.*stag|compress.*archive'         => ['T1560', 'Archive Collected Data'],
		'dns.*tunnel|dns.*exfil'                         => ['T1048.003', 'Exfiltration Over Alternative Protocol: DNS'],
		'c2|command.*control|beacon'                     => ['T1071', 'Application Layer Protocol'],
		'phish|spear'                                    => ['T1566', 'Phishing'],
		'macro|vba|\.docm'                               => ['T1204.002', 'User Execution: Malicious File'],
		'service.*create|sc create'                      => ['T1543.003', 'Create or Modify System Process: Windows Service'],
		'named.*pipe'                                    => ['T1570', 'Lateral Tool Transfer'],
		'rdp|remote desktop|mstsc'                       => ['T1021.001', 'Remote Services: Remote Desktop Protocol'],
		'ssh.*tunnel|ssh.*forward'                       => ['T1572', 'Protocol Tunneling'],
		'web.*shell|\.aspx.*upload|\.php.*shell'         => ['T1505.003', 'Server Software Component: Web Shell'],
	];

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'observations' => [
						'type'        => 'array',
						'items'       => ['type' => 'string'],
						'description' => 'List of observation strings to map',
					],
				],
				'required' => ['observations'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$observations = $params['observations'] ?? [];
		$mappings = [];
		$evidence = [];
		$seen     = [];

		foreach ($observations as $obs) {
			foreach (self::PATTERNS as $pattern => [$techId, $techName]) {
				if (preg_match("/{$pattern}/i", $obs) && !isset($seen[$techId])) {
					$seen[$techId] = true;
					$mappings[] = [
						'technique_id'       => $techId,
						'technique_name'     => $techName,
						'matched_observation'=> mb_substr($obs, 0, 200),
					];
					$evidence[] = "ttp:{$techId}:obs='" . mb_substr($obs, 0, 80) . "'";
				}
			}
		}

		$outPath = "{$case->derivedDir}/attack_map.json";
		$this->writeJson($outPath, $mappings);

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: ['techniques' => $mappings, 'count' => count($mappings)],
			evidencePointers:  $evidence,
			stdoutExcerpt:     "Mapped " . count($mappings) . " ATT&CK techniques",
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', 'attack_map'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// actor_rank
// ─────────────────────────────────────────────────────────────────

final class ActorRank extends BaseAdapter
{
	public const NAME        = 'actor_rank';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Rank scenario threat actors based on observed TTPs, IOCs, and toolmarks.';
	public const TARGET      = 'local';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'observed_techniques' => [
						'type'  => 'array', 'items' => ['type' => 'string'],
						'description' => 'Observed ATT&CK technique IDs',
					],
					'observed_iocs' => [
						'type'  => 'array', 'items' => ['type' => 'string'],
						'description' => 'Observed IOC values',
					],
					'observed_toolmarks' => [
						'type'  => 'array', 'items' => ['type' => 'string'],
						'description' => 'Tool signatures, mutexes, unique strings',
					],
				],
				'required' => ['observed_techniques'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$obsTech  = $params['observed_techniques'] ?? [];
		$obsIOCs  = $params['observed_iocs'] ?? [];
		$obsTools = $params['observed_toolmarks'] ?? [];

		// Load actor profiles
		$profilesPath = "{$case->notesDir}/actor_profiles.json";
		if (file_exists($profilesPath)) {
			$profiles = json_decode(file_get_contents($profilesPath), true);
		} else {
			// Generate template
			$profiles = [
				'_note'  => 'FILL THIS IN from scenario CTI. Each actor needs: name, known_techniques, known_iocs, known_tools',
				'actors' => [
					[
						'name'             => 'TA-EXAMPLE',
						'known_techniques' => ['T1566', 'T1059.001'],
						'known_iocs'       => [],
						'known_tools'      => ['Cobalt Strike'],
						'description'      => 'Example actor — replace with scenario CTI',
					],
				],
			];
			$this->writeJson($profilesPath, $profiles);
		}

		$rankings = [];
		foreach ($profiles['actors'] ?? [] as $actor) {
			$matches = [
				'techniques' => array_values(array_intersect($obsTech, $actor['known_techniques'] ?? [])),
				'iocs'       => array_values(array_intersect($obsIOCs, $actor['known_iocs'] ?? [])),
				'tools'      => array_filter($obsTools, function (string $t) use ($actor): bool {
					foreach ($actor['known_tools'] ?? [] as $kt) {
						if (stripos($t, $kt) !== false) return true;
					}
					return false;
				}),
			];
			$matches['tools'] = array_values($matches['tools']);

			$conflicts = [
				'techniques_not_expected' => array_values(array_diff($obsTech, $actor['known_techniques'] ?? [])),
			];

			$matchCount    = array_sum(array_map('count', $matches));
			$conflictCount = array_sum(array_map('count', $conflicts));

			$confidence = match (true) {
				$matchCount >= 3 && $conflictCount <= 1 => 'high',
				$matchCount >= 2                        => 'medium',
				default                                 => 'low',
			};

			$rankings[] = [
				'actor'          => $actor['name'],
				'match_score'    => $matchCount,
				'conflict_score' => $conflictCount,
				'matches'        => $matches,
				'conflicts'      => $conflicts,
				'confidence'     => $confidence,
			];
		}

		usort($rankings, fn($a, $b) => $b['match_score'] <=> $a['match_score'] ?: $a['conflict_score'] <=> $b['conflict_score']);

		$outPath = "{$case->derivedDir}/actor_rankings.json";
		$this->writeJson($outPath, $rankings);

		$evidence = array_map(
			fn($r) => "attribution:{$r['actor']}:matches={$r['match_score']},conflicts={$r['conflict_score']}",
			$rankings
		);

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: ['rankings' => $rankings],
			evidencePointers:  $evidence,
			stdoutExcerpt:     json_encode($rankings, JSON_PRETTY_PRINT),
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', 'actor_rank'),
		);
	}
}