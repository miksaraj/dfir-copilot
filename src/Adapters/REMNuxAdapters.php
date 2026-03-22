<?php

declare(strict_types=1);

namespace DFIRCopilot\Adapters;

use DFIRCopilot\Case\Workspace;
use DFIRCopilot\Config;
use DFIRCopilot\Executors\ExecResult;
use DFIRCopilot\Executors\SSHExecutor;
use DFIRCopilot\Executors\SharedPath;

function remnux_ssh(Config $config): SSHExecutor
{
	return SSHExecutor::fromConfig($config);
}

// ─────────────────────────────────────────────────────────────────
// strings_and_iocs
// ─────────────────────────────────────────────────────────────────

final class StringsAndIOCs extends BaseAdapter
{
	public const NAME        = 'strings_and_iocs';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Extract ASCII and Unicode strings from a binary via REMnux SSH.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'file_path'  => ['type' => 'string', 'description' => 'Path to binary (relative to case dir)'],
					'min_length' => ['type' => 'integer', 'description' => 'Minimum string length (default: 6)', 'default' => 6],
				],
				'required' => ['file_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp  = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));
		$min = (int) ($params['min_length'] ?? 6);

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;

		$transfer = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp = $transfer['path'];

		$remoteOut = "{$remoteDir}/" . pathinfo($fp, PATHINFO_FILENAME) . '_strings.txt';

		$cmd    = "strings -n {$min} '{$remoteFp}' > '{$remoteOut}' && strings -n {$min} -el '{$remoteFp}' >> '{$remoteOut}'";
		$result = $ssh->run($cmd, 120);

		$stem     = pathinfo($fp, PATHINFO_FILENAME);
		$localOut = "{$case->derivedDir}/{$stem}_strings.txt";
		$ssh->copyFrom($remoteOut, $localOut);

		if ($transfer['method'] === 'sftp') {
			$ssh->run("rm -f '{$remoteFp}'");
		}
		$ssh->run("rm -f '{$remoteOut}'");

		$lineCount = file_exists($localOut) ? count(file($localOut)) : 0;

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           $result->ok,
			producedFiles:     [$localOut],
			structuredResults: ['string_count' => $lineCount, 'output_file' => $localOut],
			evidencePointers:  ["strings:" . basename($fp) . ":lines={$lineCount}"],
			stdoutExcerpt:     "Extracted {$lineCount} strings from " . basename($fp) . " via {$transfer['method']}",
			stderrExcerpt:     mb_substr($result->stderr, 0, 500),
			execResult:        $result,
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// yara_scan
// ─────────────────────────────────────────────────────────────────

final class YARAScan extends BaseAdapter
{
	public const NAME        = 'yara_scan';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Scan a file with YARA rules on REMnux.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'file_path'  => ['type' => 'string', 'description' => 'Path to file (relative to case dir)'],
					'rules_name' => ['type' => 'string', 'description' => 'Ruleset name (default: all)', 'default' => 'all'],
				],
				'required' => ['file_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp   = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));
		$rule = $params['rules_name'] ?? 'all';

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;

		$transfer = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp = $transfer['path'];

		$remoteOut = "{$remoteDir}/" . pathinfo($fp, PATHINFO_FILENAME) . '_yara.txt';
		$rulesPath = ($rule === 'all') ? '/usr/share/yara-rules' : "/usr/share/yara-rules/{$rule}";
		$cmd       = "yara -r -s '{$rulesPath}' '{$remoteFp}' > '{$remoteOut}' 2>&1 || true";
		$result    = $ssh->run($cmd, 180);

		$stem    = pathinfo($fp, PATHINFO_FILENAME);
		$rawOut  = "{$case->derivedDir}/{$stem}_yara_raw.txt";
		$jsonOut = "{$case->derivedDir}/{$stem}_yara.json";
		$ssh->copyFrom($remoteOut, $rawOut);

		if ($transfer['method'] === 'sftp') {
			$ssh->run("rm -f '{$remoteFp}'");
		}
		$ssh->run("rm -f '{$remoteOut}'");

		$matches = [];
		if (file_exists($rawOut)) {
			foreach (file($rawOut, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
				if (!str_starts_with($line, 'error')) {
					$parts     = explode(' ', $line, 2);
					$matches[] = ['rule' => $parts[0], 'detail' => $parts[1] ?? ''];
				}
			}
		}

		$this->writeJson($jsonOut, $matches);
		$evidence = array_map(fn($m) => "yara:{$m['rule']}:" . basename($fp), $matches);

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$jsonOut, $rawOut],
			structuredResults: ['matches' => $matches, 'match_count' => count($matches)],
			evidencePointers:  $evidence,
			stdoutExcerpt:     "YARA: " . count($matches) . " rule matches on " . basename($fp),
			stderrExcerpt:     mb_substr($result->stderr, 0, 500),
			execResult:        $result,
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// capa_scan
// ─────────────────────────────────────────────────────────────────

final class CapaScan extends BaseAdapter
{
	public const NAME        = 'capa_scan';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Run capa to identify capabilities in a PE/ELF binary. Runs on REMnux.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'file_path' => ['type' => 'string', 'description' => 'Path to binary (relative to case dir)'],
				],
				'required' => ['file_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));
		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;

		$transfer   = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp   = $transfer['path'];
		$remoteJson = "{$remoteDir}/" . pathinfo($fp, PATHINFO_FILENAME) . '_capa.json';
		$remoteTxt  = "{$remoteDir}/" . pathinfo($fp, PATHINFO_FILENAME) . '_capa.txt';

		$cmd    = "capa -j '{$remoteFp}' > '{$remoteJson}' 2>/dev/null || capa '{$remoteFp}' > '{$remoteTxt}' 2>&1";
		$result = $ssh->run($cmd, 300);

		$stem      = pathinfo($fp, PATHINFO_FILENAME);
		$localJson = "{$case->derivedDir}/{$stem}_capa.json";
		$localTxt  = "{$case->derivedDir}/{$stem}_capa.txt";
		$ssh->copyFrom($remoteJson, $localJson);
		$ssh->copyFrom($remoteTxt, $localTxt);

		if ($transfer['method'] === 'sftp') {
			$ssh->run("rm -f '{$remoteFp}'");
		}
		$ssh->run("rm -f '{$remoteJson}' '{$remoteTxt}'");

		$capabilities  = [];
		$attackMappings = [];

		if (file_exists($localJson) && filesize($localJson) > 0) {
			$data = json_decode(file_get_contents($localJson), true);
			if (is_array($data)) {
				foreach ($data['rules'] ?? [] as $ruleName => $ruleInfo) {
					$capabilities[] = [
						'capability' => $ruleName,
						'namespace'  => $ruleInfo['meta']['namespace'] ?? '',
					];
					foreach ($ruleInfo['meta']['attack'] ?? [] as $att) {
						$attackMappings[] = [
							'technique'       => $att['id'] ?? '',
							'name'            => $att['technique'] ?? '',
							'from_capability' => $ruleName,
						];
					}
				}
			}
		}

		$evidence = array_map(fn($c) => "capa:{$c['capability']}", array_slice($capabilities, 0, 20));

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           $result->ok || count($capabilities) > 0,
			producedFiles:     [$localJson, $localTxt],
			structuredResults: ['capabilities' => $capabilities, 'attack_mappings' => $attackMappings, 'count' => count($capabilities)],
			evidencePointers:  $evidence,
			stdoutExcerpt:     "capa: " . count($capabilities) . " capabilities, " . count($attackMappings) . " ATT&CK mappings",
			stderrExcerpt:     mb_substr($result->stderr, 0, 500),
			execResult:        $result,
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// vol3_triage (v1.1 — Linux plugin support + shared folder)
// ─────────────────────────────────────────────────────────────────

final class Vol3Triage extends BaseAdapter
{
	public const NAME        = 'vol3_triage';
	public const VERSION     = '1.1.0';
	public const DESCRIPTION = 'Run Volatility 3 triage pack on a memory image. Supports Windows and Linux profiles.';
	public const TARGET      = 'remnux';

	private const WINDOWS_PLUGINS = [
		'windows.pslist.PsList',
		'windows.pstree.PsTree',
		'windows.netscan.NetScan',
		'windows.cmdline.CmdLine',
		'windows.dlllist.DllList',
	];

	private const LINUX_PLUGINS = [
		'linux.pslist.PsList',
		'linux.pstree.PsTree',
		'linux.sockstat.Sockstat',
		'linux.bash.Bash',
		'linux.lsmod.Lsmod',
	];

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'memory_image' => [
						'type'        => 'string',
						'description' => 'Path to memory image (relative to case dir). Supports .mem, .raw, .lime, .E01',
					],
					'profile' => [
						'type'        => 'string',
						'enum'        => ['windows', 'linux'],
						'description' => 'OS profile: windows (default) or linux',
						'default'     => 'windows',
					],
					'plugins' => [
						'type'  => 'array',
						'items' => ['type' => 'string'],
						'description' => 'Override: specific plugins to run (default: triage pack for the selected profile)',
					],
				],
				'required' => ['memory_image'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp      = $this->resolveFilePath($case, $this->requireParam($params, 'memory_image'));
		$profile = $params['profile'] ?? 'windows';
		$plugins = $params['plugins'] ?? ($profile === 'linux' ? self::LINUX_PLUGINS : self::WINDOWS_PLUGINS);

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;

		$ssh->run("mkdir -p {$remoteDir}");
		$transfer = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp = $transfer['path'];

		$pluginResults = [];
		$producedFiles = [];
		$evidence      = [];

		foreach ($plugins as $plugin) {
			$short      = strtolower(array_slice(explode('.', $plugin), -1)[0]);
			$remoteJson = "{$remoteDir}/vol3_{$short}.json";
			$remoteTxt  = "{$remoteDir}/vol3_{$short}.txt";

			$cmd = "vol -f '{$remoteFp}' -r json {$plugin} > '{$remoteJson}' 2>/dev/null || vol -f '{$remoteFp}' {$plugin} > '{$remoteTxt}' 2>&1";
			$ssh->run($cmd, 300);

			$localJson = "{$case->derivedDir}/vol3_{$short}.json";
			$localTxt  = "{$case->derivedDir}/vol3_{$short}.txt";
			$ssh->copyFrom($remoteJson, $localJson);
			$ssh->copyFrom($remoteTxt, $localTxt);

			$records = [];
			if (file_exists($localJson) && filesize($localJson) > 0) {
				$decoded = json_decode(file_get_contents($localJson), true);
				if (is_array($decoded)) {
					$records = $decoded;
					$pluginResults[$short] = $decoded;
				}
			}

			if (empty($records) && file_exists($localTxt)) {
				$pluginResults[$short] = ['raw_output' => mb_substr(file_get_contents($localTxt), 0, 5000)];
			}

			$producedFiles[] = $localJson;
			$producedFiles[] = $localTxt;
			$count = is_array($records) && !isset($records['raw_output']) ? count($records) : '?';
			$evidence[] = "vol3:{$short}:records={$count}";
		}

		$ssh->run("rm -f {$remoteDir}/vol3_*.json {$remoteDir}/vol3_*.txt");

		if ($transfer['method'] === 'sftp') {
			$ssh->run("rm -f '{$remoteFp}'");
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     $producedFiles,
			structuredResults: $pluginResults,
			evidencePointers:  $evidence,
			stdoutExcerpt:     "Vol3 triage ({$profile}): " . count($plugins) . " plugins run via {$transfer['method']}",
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, "ssh:{$config->remnuxHost}", 'vol3_triage'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// timeline_build
// ─────────────────────────────────────────────────────────────────

final class TimelineBuild extends BaseAdapter
{
	public const NAME        = 'timeline_build';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Build a super timeline from a disk image using plaso/log2timeline on REMnux.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'image_path'    => ['type' => 'string', 'description' => 'Path to disk image or artifact directory'],
					'output_format' => ['type' => 'string', 'enum' => ['csv', 'json'], 'default' => 'csv'],
				],
				'required' => ['image_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp     = $this->resolveFilePath($case, $this->requireParam($params, 'image_path'));
		$format = $params['output_format'] ?? 'csv';

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;

		$ssh->run("mkdir -p {$remoteDir}");
		$transfer = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp = $transfer['path'];

		$plasoDb   = "{$remoteDir}/timeline.plaso";
		$remoteOut = "{$remoteDir}/timeline.{$format}";

		$resultL2t = $ssh->run("log2timeline.py --status_view none '{$plasoDb}' '{$remoteFp}' 2>&1", 600);

		$exportCmd = ($format === 'csv')
			? "psort.py -o l2tcsv -w '{$remoteOut}' '{$plasoDb}' 2>&1"
			: "psort.py -o json_line -w '{$remoteOut}' '{$plasoDb}' 2>&1";
		$resultExport = $ssh->run($exportCmd, 300);

		$localOut = "{$case->timelinesDir}/timeline.{$format}";
		$ssh->copyFrom($remoteOut, $localOut);

		if ($transfer['method'] === 'sftp') {
			$ssh->run("rm -f '{$remoteFp}'");
		}
		$ssh->run("rm -f '{$plasoDb}' '{$remoteOut}'");

		$lineCount = file_exists($localOut) ? count(file($localOut)) : 0;

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           $resultL2t->ok || file_exists($localOut),
			producedFiles:     [$localOut],
			structuredResults: ['output_file' => $localOut, 'format' => $format, 'event_count' => $lineCount],
			evidencePointers:  ["timeline:events={$lineCount}"],
			stdoutExcerpt:     "Timeline: {$lineCount} events in {$format} via {$transfer['method']}",
			stderrExcerpt:     mb_substr($resultL2t->stderr . $resultExport->stderr, 0, 500),
			execResult:        $resultL2t,
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// pcap_summary
// ─────────────────────────────────────────────────────────────────

final class PCAPSummary extends BaseAdapter
{
	public const NAME        = 'pcap_summary';
	public const VERSION     = '1.1.0';
	public const DESCRIPTION = 'Extract network summary from a PCAP: conversations, DNS, HTTP, TLS SNI. Supports TLS decryption via keylog file.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'pcap_path' => ['type' => 'string', 'description' => 'Path to PCAP/PCAPNG file (relative to case dir)'],
					'keylog_file' => [
						'type'        => 'string',
						'description' => 'Optional: path to TLS key log file for decryption (relative to case dir)',
						'default'     => '',
					],
				],
				'required' => ['pcap_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp      = $this->resolveFilePath($case, $this->requireParam($params, 'pcap_path'));
		$keylog  = ($params['keylog_file'] ?? '') !== '' ? $this->resolveFilePath($case, $params['keylog_file']) : '';

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;

		$ssh->run("mkdir -p {$remoteDir}");
		$transfer = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp = $transfer['path'];

		// Transfer keylog file if provided
		$remoteKeylog = '';
		if ($keylog !== '' && file_exists($keylog)) {
			$klTransfer   = SharedPath::ensureOnREMnux($keylog, $config, $ssh, $remoteDir);
			$remoteKeylog = $klTransfer['path'];
		}

		// Build tshark options
		$tlsOpt = $remoteKeylog !== '' ? "-o tls.keylog_file:{$remoteKeylog}" : '';

		$results = [];

		$r = $ssh->run("tshark -r '{$remoteFp}' {$tlsOpt} -q -z conv,tcp 2>/dev/null | head -100");
		$results['tcp_conversations'] = $r->stdout;

		$r = $ssh->run("tshark -r '{$remoteFp}' {$tlsOpt} -Y 'dns.qry.name' -T fields -e dns.qry.name 2>/dev/null | sort -u");
		$results['dns_queries'] = array_filter(explode("\n", trim($r->stdout)));

		$r = $ssh->run("tshark -r '{$remoteFp}' {$tlsOpt} -Y 'http.request' -T fields -e http.host -e http.request.uri 2>/dev/null | head -50");
		$results['http_requests'] = $r->stdout;

		$r = $ssh->run("tshark -r '{$remoteFp}' {$tlsOpt} -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u");
		$results['tls_sni'] = array_filter(explode("\n", trim($r->stdout)));

		// If keylog provided, also extract decrypted HTTP/2 traffic
		if ($remoteKeylog !== '') {
			$r = $ssh->run("tshark -r '{$remoteFp}' {$tlsOpt} -Y 'http2.headers' -T fields -e http2.headers.authority -e http2.headers.path 2>/dev/null | head -50");
			$results['http2_requests'] = $r->stdout;

			$results['tls_decryption'] = 'enabled';
		}

		$r = $ssh->run("capinfos '{$remoteFp}' 2>/dev/null");
		$results['pcap_info'] = $r->stdout;

		// Cleanup
		if ($transfer['method'] === 'sftp') {
			$ssh->run("rm -f '{$remoteFp}'");
		}
		if ($remoteKeylog !== '' && $klTransfer['method'] === 'sftp') {
			$ssh->run("rm -f '{$remoteKeylog}'");
		}

		$stem    = pathinfo($fp, PATHINFO_FILENAME);
		$outPath = "{$case->derivedDir}/{$stem}_pcap_summary.json";
		$this->writeJson($outPath, $results);

		$evidence = [];
		foreach (array_slice($results['dns_queries'] ?? [], 0, 20) as $dns) {
			$evidence[] = "pcap:dns:{$dns}";
		}
		foreach (array_slice($results['tls_sni'] ?? [], 0, 20) as $sni) {
			$evidence[] = "pcap:tls_sni:{$sni}";
		}

		$dnsCount = count($results['dns_queries'] ?? []);
		$sniCount = count($results['tls_sni'] ?? []);
		$tlsNote  = $remoteKeylog !== '' ? ' (TLS decrypted)' : '';

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: $results,
			evidencePointers:  $evidence,
			stdoutExcerpt:     "PCAP: {$dnsCount} DNS, {$sniCount} TLS SNI{$tlsNote}",
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, "ssh:{$config->remnuxHost}", 'pcap_summary'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// inject_pdf_read
// ─────────────────────────────────────────────────────────────────

/**
 * Extracts text from inject PDFs — the challenge briefing documents that
 * describe what the analyst is asked to find.
 *
 * Every LS challenge includes a *_inject.pdf. Feeding its text to the agent
 * lets it understand the questions without you having to type them in.
 *
 * Uses pdftotext (from poppler-utils) on REMnux.
 */
final class InjectPdfRead extends BaseAdapter
{
	public const NAME        = 'inject_pdf_read';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Extract text from an inject PDF (challenge briefing). Returns the questions/tasks the analyst needs to answer.';
	public const TARGET      = 'remnux';

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
						'description' => 'Path to the inject PDF (relative to case dir)',
					],
				],
				'required' => ['file_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));
		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;

		$transfer = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp = $transfer['path'];

		// Extract text with pdftotext (poppler-utils, standard on REMnux)
		$remoteOut = "{$remoteDir}/" . pathinfo($fp, PATHINFO_FILENAME) . '_text.txt';
		$result    = $ssh->run("pdftotext -layout '{$remoteFp}' '{$remoteOut}' 2>&1", 30);

		$stem     = pathinfo($fp, PATHINFO_FILENAME);
		$localOut = "{$case->derivedDir}/{$stem}_inject_text.txt";
		$ssh->copyFrom($remoteOut, $localOut);

		if ($transfer['method'] === 'sftp') {
			$ssh->run("rm -f '{$remoteFp}'");
		}
		$ssh->run("rm -f '{$remoteOut}'");

		$text = file_exists($localOut) ? trim(file_get_contents($localOut)) : '';

		if ($text === '') {
			// Fallback: try pdftotext without -layout
			$result2 = $ssh->run("pdftotext '{$remoteFp}' - 2>/dev/null", 30);
			$text    = trim($result2->stdout);
			if ($text !== '') {
				file_put_contents($localOut, $text);
			}
		}

		// Extract questions/tasks (lines with numbers, Q:, interrogatives, directives)
		$questions = [];
		foreach (explode("\n", $text) as $i => $line) {
			$trimmed = trim($line);
			if ($trimmed === '') continue;
			if (preg_match('/^\d+[\.\)]\s/', $trimmed) ||
				preg_match('/^Q\d*[\.:]/i', $trimmed) ||
				str_contains($trimmed, '?') ||
				preg_match('/^(what|who|when|where|which|how|find|identify|determine|describe|explain|list|name|provide)/i', $trimmed)) {
				$questions[] = [
					'line'     => $i + 1,
					'question' => $trimmed,
				];
			}
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           $text !== '',
			producedFiles:     [$localOut],
			structuredResults: [
				'full_text'      => mb_substr($text, 0, 8000),
				'questions'      => $questions,
				'question_count' => count($questions),
				'char_count'     => mb_strlen($text),
			],
			evidencePointers:  array_map(
				fn($q) => "inject:line={$q['line']}:{$q['question']}",
				array_slice($questions, 0, 20)
			),
			stdoutExcerpt:     "Extracted " . mb_strlen($text) . " chars, " . count($questions) . " questions from inject PDF",
			stderrExcerpt:     mb_substr($result->stderr, 0, 500),
			execResult:        $result,
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// evtx_parse
// ─────────────────────────────────────────────────────────────────

/**
 * Parses Windows Event Log (.evtx) files into structured JSON.
 *
 * Uses evtx_dump (Rust) or python-evtx on REMnux.
 *
 * Relevant for challenges tagged: #eventlogs, #systemlog, #pcanalysis
 */
final class EvtxParse extends BaseAdapter
{
	public const NAME        = 'evtx_parse';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Parse Windows Event Log (.evtx) files. Returns structured events as JSON with optional filtering by event ID.';
	public const TARGET      = 'remnux';

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
						'description' => 'Path to .evtx file (relative to case dir)',
					],
					'event_ids' => [
						'type'        => 'array',
						'items'       => ['type' => 'integer'],
						'description' => 'Optional: filter to specific event IDs (e.g. [4624, 4625, 4688, 7045])',
					],
					'max_events' => [
						'type'        => 'integer',
						'description' => 'Maximum events to return (default: 500)',
						'default'     => 500,
					],
				],
				'required' => ['file_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp        = $this->resolveFilePath($case, $this->requireParam($params, 'file_path'));
		$eventIds  = $params['event_ids'] ?? [];
		$maxEvents = (int) ($params['max_events'] ?? 500);

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;

		$transfer = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp = $transfer['path'];

		$stem       = pathinfo($fp, PATHINFO_FILENAME);
		$remoteJson = "{$remoteDir}/{$stem}_evtx.json";

		// Try evtx_dump (Rust, fast) first, fall back to python-evtx
		$cmd = <<<BASH
if command -v evtx_dump &>/dev/null; then
  evtx_dump -o jsonl '{$remoteFp}' > '{$remoteJson}' 2>/dev/null
elif python3 -c "import Evtx" 2>/dev/null; then
  python3 -c "
import Evtx.Evtx as evtx
import json, sys
with evtx.Evtx('{$remoteFp}') as log:
  for record in log.records():
    try:
      print(json.dumps({'EventRecordID': record.record_num(), 'xml': record.xml()}))
    except: pass
" > '{$remoteJson}' 2>/dev/null
else
  echo 'NO_EVTX_TOOL' > '{$remoteJson}'
fi
BASH;

		$result = $ssh->run($cmd, 120);

		$localJson = "{$case->derivedDir}/{$stem}_evtx.json";
		$ssh->copyFrom($remoteJson, $localJson);

		if ($transfer['method'] === 'sftp') {
			$ssh->run("rm -f '{$remoteFp}'");
		}
		$ssh->run("rm -f '{$remoteJson}'");

		// Parse events
		$events     = [];
		$eventCount = 0;
		$filtered   = 0;

		if (file_exists($localJson)) {
			$content = file_get_contents($localJson);

			if (str_contains($content, 'NO_EVTX_TOOL')) {
				return $this->errorResult(
					"No EVTX parser found on REMnux. Install: sudo apt install python3-evtx (or cargo install evtx)"
				);
			}

			foreach (explode("\n", $content) as $line) {
				$line = trim($line);
				if ($line === '') continue;

				$record = json_decode($line, true);
				if (!is_array($record)) continue;
				$eventCount++;

				// Extract event ID from JSON or XML
				$eid = $record['Event']['System']['EventID'] ?? null;
				if ($eid === null && isset($record['xml'])) {
					if (preg_match('/<EventID[^>]*>(\d+)</', $record['xml'], $m)) {
						$eid = (int) $m[1];
					}
				}

				if (!empty($eventIds) && $eid !== null && !in_array((int) $eid, $eventIds, true)) {
					$filtered++;
					continue;
				}

				if (count($events) < $maxEvents) {
					$events[] = $record;
				}
			}
		}

		// Summarise event ID frequencies
		$eidCounts = [];
		foreach ($events as $e) {
			$eid = $e['Event']['System']['EventID'] ?? 'unknown';
			$eidCounts[$eid] = ($eidCounts[$eid] ?? 0) + 1;
		}
		arsort($eidCounts);

		$this->writeJson($localJson, $events);

		$evidence = [];
		foreach (array_slice($eidCounts, 0, 10, true) as $eid => $count) {
			$evidence[] = "evtx:{$stem}:EventID={$eid}:count={$count}";
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($events),
			producedFiles:     [$localJson],
			structuredResults: [
				'total_events'     => $eventCount,
				'returned_events'  => count($events),
				'filtered_out'     => $filtered,
				'event_id_summary' => array_slice($eidCounts, 0, 20, true),
				'events'           => array_slice($events, 0, 50),
			],
			evidencePointers:  $evidence,
			stdoutExcerpt:     "EVTX: {$eventCount} total events, " . count($events) . " returned, top IDs: " . json_encode(array_slice($eidCounts, 0, 5, true)),
			stderrExcerpt:     mb_substr($result->stderr, 0, 500),
			execResult:        $result,
		);
	}
}