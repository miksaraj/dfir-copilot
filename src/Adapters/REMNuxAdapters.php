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

		$ext = strtolower(pathinfo($fp, PATHINFO_EXTENSION));
		// E01, Raw images are notoriously large and will hang strings
		if (in_array($ext, ['e01', 'ex01', 'raw', 'dd', 'img', 'vmdk'], true)) {
			return $this->errorResult("strings_and_iocs cannot be run directly on disk images ({$ext}). Use disk_timeline or mft_search instead.");
		}
		
		$size = filesize($fp);
		if ($size > 500 * 1024 * 1024) {
			$mb = round($size / 1024 / 1024);
			return $this->errorResult("File too large for strings_and_iocs: {$mb} MB. Limit is 500 MB to prevent timeouts.");
		}

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

		$ext = strtolower(pathinfo($fp, PATHINFO_EXTENSION));
		if (in_array($ext, ['e01', 'ex01', 'raw', 'dd', 'img', 'vmdk'], true)) {
			return $this->errorResult("yara_scan cannot be run directly on disk images ({$ext}). Extract files first (e.g. via mft_search), then scan them.");
		}
		
		$size = filesize($fp);
		if ($size > 1024 * 1024 * 1024) {
			$mb = round($size / 1024 / 1024);
			return $this->errorResult("File too large for yara_scan: {$mb} MB. Limit is 1 GB mapped to prevent timeouts.");
		}

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
 * Runs pdftotext locally first (the host always has the file and
 * poppler-utils is a standard dependency). Falls back to REMnux SSH only
 * when pdftotext is absent on the host.
 */
final class InjectPdfRead extends BaseAdapter
{
	public const NAME        = 'inject_pdf_read';
	public const VERSION     = '1.1.0';
	public const DESCRIPTION = 'Extract text from an inject PDF (challenge briefing). Returns the questions/tasks the analyst needs to answer.';
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

		$stem     = pathinfo($fp, PATHINFO_FILENAME);
		$localOut = "{$case->derivedDir}/{$stem}_inject_text.txt";

		$text   = '';
		$method = '';
		$stderr = '';

		// ── 1. Try local pdftotext (preferred — no SSH round-trip needed) ──
		$hasPdftotext = trim(shell_exec('which pdftotext 2>/dev/null') ?? '') !== '';

		if ($hasPdftotext) {
			// -layout preserves column alignment; fall back without it for
			// PDFs where it produces empty output (some Word-exported files).
			$escapedFp  = escapeshellarg($fp);
			$escapedOut = escapeshellarg($localOut);

			exec("pdftotext -layout {$escapedFp} {$escapedOut} 2>/dev/null");

			if (file_exists($localOut)) {
				$text = trim(file_get_contents($localOut));
			}

			// If -layout produced nothing, retry in stdout mode without -layout
			if ($text === '') {
				$raw  = shell_exec("pdftotext {$escapedFp} - 2>/dev/null") ?? '';
				$text = trim($raw);
				if ($text !== '') {
					file_put_contents($localOut, $text);
				}
			}

			$method = 'local';
		}

		// ── 2. Fallback: REMnux SSH (when pdftotext not on host) ──────────
		if ($text === '') {
			try {
				$ssh       = remnux_ssh($config);
				$remoteDir = $config->remnuxWorkDir;
				$ssh->run("mkdir -p {$remoteDir}");

				$transfer  = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
				$remoteFp  = $transfer['path'];
				$remoteOut = "{$remoteDir}/{$stem}_text.txt";

				// Run both attempts while the remote file is still present,
				// then clean up — the original code deleted first, then fell
				// back, which caused "file not found" on the second attempt.
				$r1 = $ssh->run("pdftotext -layout '{$remoteFp}' '{$remoteOut}' 2>&1", 30);
				$ssh->copyFrom($remoteOut, $localOut);
				$text   = file_exists($localOut) ? trim(file_get_contents($localOut)) : '';
				$stderr = $r1->stderr;

				if ($text === '') {
					$r2   = $ssh->run("pdftotext '{$remoteFp}' - 2>/dev/null", 30);
					$text = trim($r2->stdout);
					if ($text !== '') {
						file_put_contents($localOut, $text);
					}
				}

				// Cleanup now that both attempts are done
				$ssh->run("rm -f '{$remoteOut}'");
				if ($transfer['method'] === 'sftp') {
					$ssh->run("rm -f '{$remoteFp}'");
				}

				$method = "ssh:{$config->remnuxHost}";
			} catch (\Throwable $e) {
				$stderr = $e->getMessage();
			}
		}

		if ($text === '') {
			return $this->errorResult(
				"pdftotext produced no output. Is poppler-utils installed? " .
				($stderr !== '' ? "Stderr: {$stderr}" : "Try: sudo apt install poppler-utils")
			);
		}

		// ── Parse into sections by ALL-CAPS heading ───────────────────────
		// Inject PDFs use headings like DESCRIPTION, TASKING, REPORTING rather
		// than question syntax, so we detect those and bucket lines beneath
		// them. The agent always has full_text to read directly.
		$sections       = [];
		$currentSection = 'HEADER';
		$buffer         = [];

		$flushSection = function () use (&$sections, &$currentSection, &$buffer): void {
			$body = trim(implode("\n", $buffer));
			if ($body !== '') {
				$sections[$currentSection] = $body;
			}
			$buffer = [];
		};

		foreach (explode("\n", $text) as $line) {
			$trimmed = trim($line);
			// A section heading: 1–4 ALL-CAPS words on their own line,
			// no punctuation (avoids matching "EXERCISE-EXERCISE-EXERCISE").
			if (preg_match('/^[A-Z][A-Z\s]{1,40}$/', $trimmed) &&
				preg_match('/^[A-Z]+(?:\s+[A-Z]+){0,3}$/', $trimmed)) {
				$flushSection();
				$currentSection = $trimmed;
			} else {
				$buffer[] = $line;
			}
		}
		$flushSection();

		// Evidence pointers: one per section heading found
		$evidence = [];
		foreach ($sections as $heading => $body) {
			$evidence[] = "inject:section={$heading}:" . mb_substr($body, 0, 80);
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$localOut],
			structuredResults: [
				'full_text'     => mb_substr($text, 0, 8000),
				'sections'      => $sections,
				'section_count' => count($sections),
				'char_count'    => mb_strlen($text),
				'method'        => $method,
			],
			evidencePointers:  array_slice($evidence, 0, 20),
			stdoutExcerpt:     "Extracted " . mb_strlen($text) . " chars across " . count($sections) . " sections from inject PDF (via {$method})",
			stderrExcerpt:     mb_substr($stderr, 0, 500),
			execResult:        new ExecResult(0, '', $stderr, 0, $method, 'pdftotext'),
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
// ─────────────────────────────────────────────────────────────────
// pcap_filter
// ─────────────────────────────────────────────────────────────────

final class PcapFilter extends BaseAdapter
{
	public const NAME        = 'pcap_filter';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Filter a PCAP/PCAPNG with a Wireshark display filter and extract specific fields using tshark. Use for targeted queries — e.g. filter by IP, HTTP requests, DNS queries — more detailed than pcap_summary.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'pcap_path' => ['type' => 'string', 'description' => 'Path to PCAP/PCAPNG (relative to case dir).'],
					'filter'    => ['type' => 'string', 'description' => 'Wireshark display filter, e.g. "ip.addr==18.165.122.89", "http.request", "tcp.port==443".'],
					'fields'    => ['type' => 'array', 'items' => ['type' => 'string'], 'description' => 'tshark fields to extract, e.g. ["ip.src","ip.dst","http.request.uri","dns.qry.name"]. Defaults to frame time + src/dst + info.', 'default' => []],
					'max_packets' => ['type' => 'integer', 'description' => 'Max packets to return (default: 500).', 'default' => 500],
				],
				'required' => ['pcap_path', 'filter'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp         = $this->resolveFilePath($case, $this->requireParam($params, 'pcap_path'));
		$filter     = $this->requireParam($params, 'filter');
		$fields     = $params['fields'] ?? [];
		$maxPackets = (int) ($params['max_packets'] ?? 500);

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;
		$ssh->run("mkdir -p '{$remoteDir}'");
		$transfer  = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp  = $transfer['path'];

		if (empty($fields)) {
			$fields = ['frame.time', 'ip.src', 'ip.dst', '_ws.col.Info'];
		}

		$fieldArgs = implode(' ', array_map(fn($f) => '-e ' . escapeshellarg($f), $fields));
		$remoteOut = "{$remoteDir}/pcap_filter_out.txt";
		$r = $ssh->run(
"tshark -r '{$remoteFp}' -Y " . escapeshellarg($filter)
. " -T fields {$fieldArgs} -E separator='|' -c {$maxPackets} > '{$remoteOut}' 2>/dev/null",
120,
);

		$stem     = pathinfo($fp, PATHINFO_FILENAME);
		$localOut = "{$case->derivedDir}/{$stem}_filtered.txt";
		$ssh->copyFrom($remoteOut, $localOut);
		$ssh->run("rm -f '{$remoteOut}'");
		if ($transfer['method'] === 'sftp') $ssh->run("rm -f '{$remoteFp}'");

		$lines   = array_filter(array_map('trim', explode("\n", file_exists($localOut) ? file_get_contents($localOut) : '')));
		$count   = count($lines);
		$records = [];
		$evidence = [];
		foreach (array_slice($lines, 0, 200) as $l) {
			$parts     = explode('|', $l);
			$records[] = array_combine(array_slice($fields, 0, count($parts)), $parts) ?: ['raw' => $l];
			$evidence[] = 'pcap_filter:' . mb_substr($l, 0, 120);
		}

		$outJson = "{$case->derivedDir}/{$stem}_filtered.json";
		$this->writeJson($outJson, $records);

		return new AdapterResult(
adapterName:       self::NAME,
success:           $count > 0,
			producedFiles:     [$outJson, $localOut],
			structuredResults: ['filter' => $filter, 'packet_count' => $count, 'fields' => $fields, 'records' => $records],
			evidencePointers:  array_slice($evidence, 0, 50),
			stdoutExcerpt:     "pcap_filter '{$filter}': {$count} packets matched",
			stderrExcerpt:     mb_substr($r->stderr, 0, 300),
			execResult:        new ExecResult($r->exitCode, '', $r->stderr, 0, "ssh:{$config->remnuxHost}", 'pcap_filter'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// pcap_carve
// ─────────────────────────────────────────────────────────────────

final class PcapCarve extends BaseAdapter
{
	public const NAME        = 'pcap_carve';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Extract TCP streams and transferred files from a PCAP using tcpflow on REMnux. Recovers files dropped via HTTP, uploaded via FTP, or exfiltrated over raw TCP. Returns a list of carved streams with magic-byte identification.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'pcap_path' => ['type' => 'string', 'description' => 'Path to PCAP/PCAPNG (relative to case dir).'],
					'filter'    => ['type' => 'string', 'description' => 'Optional BPF filter, e.g. "host 18.165.122.89" or "port 80".', 'default' => ''],
				],
				'required' => ['pcap_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp  = $this->resolveFilePath($case, $this->requireParam($params, 'pcap_path'));
		$bpf = trim($params['filter'] ?? '');

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;
		$ssh->run("mkdir -p '{$remoteDir}'");
		$transfer  = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp  = $transfer['path'];

		$carveDir = "{$remoteDir}/pcap_carve_out";
		$ssh->run("mkdir -p '{$carveDir}'");

		$bpfArg = $bpf !== '' ? escapeshellarg($bpf) : '';
		$r = $ssh->run("tcpflow -r '{$remoteFp}' -o '{$carveDir}' {$bpfArg} 2>/dev/null", 300);

		$listR = $ssh->run(
"find '{$carveDir}' -type f ! -name '*.html' ! -name 'report*' | head -100"
. " | while read f; do sz=\$(stat -c%s \"\$f\" 2>/dev/null||echo 0); mg=\$(file -b \"\$f\" 2>/dev/null|head -c80); echo \"\$sz|\$mg|\$f\"; done",
60,
);

		$stem       = pathinfo($fp, PATHINFO_FILENAME);
		$localCarve = "{$case->derivedDir}/pcap_carved_{$stem}";
		if (!is_dir($localCarve)) mkdir($localCarve, 0755, true);

		$carved      = [];
		$evidence    = [];
		$interesting = ['PE32', 'ELF', 'PDF document', 'Zip', 'script', 'executable', 'JPEG', 'PNG', 'XML'];

		foreach (array_filter(array_map('trim', explode("\n", $listR->stdout))) as $line) {
			$parts = explode('|', $line, 3);
			if (count($parts) < 3) continue;
			[$size, $magic, $remotePath] = $parts;
			$fname   = basename($remotePath);
			$entry   = ['file' => $fname, 'size_bytes' => (int) $size, 'magic' => trim($magic)];
			$carved[] = $entry;
			foreach ($interesting as $kw) {
				if (stripos($magic, $kw) !== false) {
					$ssh->copyFrom($remotePath, "{$localCarve}/{$fname}");
					$evidence[] = "carved:{$kw}:{$fname}:size={$size}";
					break;
				}
			}
		}

		$ssh->run("rm -rf '{$carveDir}'");
		if ($transfer['method'] === 'sftp') $ssh->run("rm -f '{$remoteFp}'");

		$outJson = "{$case->derivedDir}/{$stem}_pcap_carved.json";
		$this->writeJson($outJson, $carved);

		return new AdapterResult(
adapterName:       self::NAME,
success:           !empty($carved),
producedFiles:     [$outJson],
structuredResults: ['total_streams' => count($carved), 'interesting_count' => count($evidence), 'carved' => $carved],
			evidencePointers:  array_slice($evidence, 0, 30),
			stdoutExcerpt:     "pcap_carve: " . count($carved) . " streams, " . count($evidence) . " interesting files",
			stderrExcerpt:     mb_substr($r->stderr, 0, 300),
			execResult:        new ExecResult($r->exitCode, '', $r->stderr, 0, "ssh:{$config->remnuxHost}", 'pcap_carve'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// oletools_analyze
// ─────────────────────────────────────────────────────────────────

final class OletoolsAnalyze extends BaseAdapter
{
	public const NAME        = 'oletools_analyze';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Analyse Office documents (doc/docx/xls/xlsm/ppt/rtf) for VBA macros, embedded scripts, and malicious patterns using oletools (olevba + mraptor) on REMnux. Critical for phishing and malicious document scenarios.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'file_path' => ['type' => 'string', 'description' => 'Path to Office document (relative to case dir).'],
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
		$ssh->run("mkdir -p '{$remoteDir}'");
		$transfer  = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp  = $transfer['path'];

		$stem      = pathinfo($fp, PATHINFO_FILENAME);
		$remoteOut = "{$remoteDir}/olevba_out.txt";

		$rOle  = $ssh->run("olevba --json '{$remoteFp}' > '{$remoteOut}' 2>/dev/null || olevba '{$remoteFp}' > '{$remoteOut}' 2>&1", 120);
		$rMrap = $ssh->run("mraptor '{$remoteFp}' 2>/dev/null", 60);

		$localOle = "{$case->derivedDir}/{$stem}_olevba.txt";
		$ssh->copyFrom($remoteOut, $localOle);
		$ssh->run("rm -f '{$remoteOut}'");
		if ($transfer['method'] === 'sftp') $ssh->run("rm -f '{$remoteFp}'");

		$raw  = file_exists($localOle) ? file_get_contents($localOle) : '';
		$data = json_decode($raw, true);
		if (!is_array($data)) {
			$data = ['raw_output' => mb_substr($raw, 0, 6000)];
		}

		$mrapLine = trim($rMrap->stdout);
		$risk     = match(true) {
			str_contains($mrapLine, 'SUSPICIOUS')     => 'suspicious',
			str_contains($mrapLine, 'NOT SUSPICIOUS') => 'not_suspicious',
			str_contains($mrapLine, 'ERROR')           => 'error',
			default                                    => 'unknown',
		};

		$evidence   = ["ole:" . basename($fp) . ":mraptor={$risk}"];
		$hasMacros  = false;
		foreach ($data['macros'] ?? [] as $m) {
			$hasMacros  = true;
			$evidence[] = "ole:macro:" . mb_substr($m['vba_code'] ?? '', 0, 80);
		}
		foreach ($data['iocs'] ?? [] as $ioc) {
			$evidence[] = "ole:ioc:" . mb_substr((string)($ioc['value'] ?? $ioc), 0, 80);
		}
		if (!$hasMacros && str_contains($mrapLine, 'SUSPICIOUS')) {
			$hasMacros = true;
		}

		$outJson = "{$case->derivedDir}/{$stem}_oletools.json";
		$this->writeJson($outJson, ['file' => basename($fp), 'mraptor' => ['risk' => $risk, 'output' => $mrapLine], 'olevba' => $data]);

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outJson, $localOle],
			structuredResults: ['risk' => $risk, 'has_macros' => $hasMacros, 'mraptor' => $mrapLine, 'olevba' => $data],
			evidencePointers:  array_slice($evidence, 0, 30),
			stdoutExcerpt:     "oletools: risk={$risk}, macros=" . ($hasMacros ? 'YES' : 'NO'),
			stderrExcerpt:     mb_substr($rOle->stderr, 0, 300),
			execResult:        new ExecResult($rOle->exitCode, '', $rOle->stderr, 0, "ssh:{$config->remnuxHost}", 'oletools_analyze'),
		);
	}
}
// ─────────────────────────────────────────────────────────────────
// evtx_bulk_query
// ─────────────────────────────────────────────────────────────────
final class EvtxBulkQuery extends BaseAdapter
{
	public const NAME        = 'evtx_bulk_query';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Parse and correlate multiple Windows EVTX files simultaneously (e.g. from a KAPE triage with 30+ log channels). Merges Security, System, Application, PowerShell Operational, and Sysmon events into a single chronological stream filtered by event ID, time window, username, or process name. Essential for cross-channel attack chain reconstruction.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'evtx_dir' => [
						'type'        => 'string',
						'description' => 'Directory containing multiple .evtx files (e.g. KAPE_Triage/C/Windows/System32/winevt/Logs/). Relative to case dir.',
					],
					'event_ids' => [
						'type'        => 'array',
						'items'       => ['type' => 'integer'],
						'description' => 'Filter to specific event IDs across all channels (e.g. [4624,4625,4688,4104,7045]). Empty = all events.',
					],
					'username' => [
						'type'        => 'string',
						'description' => 'Return only events referencing this user/account name (case-insensitive substring).',
					],
					'process_name' => [
						'type'        => 'string',
						'description' => 'Return only events referencing this process name (case-insensitive substring).',
					],
					'keyword' => [
						'type'        => 'string',
						'description' => 'Return only events whose XML contains this keyword (case-insensitive).',
					],
					'channels' => [
						'type'        => 'array',
						'items'       => ['type' => 'string'],
						'description' => 'Limit to specific EVTX filenames (without path) e.g. ["Security.evtx","Microsoft-Windows-PowerShell%4Operational.evtx"]. Default: all.',
					],
					'time_from' => [
						'type'        => 'string',
						'description' => 'Start of time window (ISO-8601 or YYYY-MM-DD HH:MM:SS).',
					],
					'time_to' => [
						'type'        => 'string',
						'description' => 'End of time window.',
					],
					'max_events' => [
						'type'        => 'integer',
						'description' => 'Maximum events to return across all channels (default: 500).',
						'default'     => 500,
					],
				],
				'required' => ['evtx_dir'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$evtxDir    = $this->resolveFilePath($case, $this->requireParam($params, 'evtx_dir'));
		$eventIds   = array_map('intval', $params['event_ids']   ?? []);
		$username   = strtolower($params['username']    ?? '');
		$procName   = strtolower($params['process_name'] ?? '');
		$keyword    = strtolower($params['keyword']     ?? '');
		$channels   = array_map('strtolower', $params['channels'] ?? []);
		$timeFrom   = $params['time_from'] ?? '';
		$timeTo     = $params['time_to']   ?? '';
		$maxEvents  = (int) ($params['max_events'] ?? 500);

		if (!is_dir($evtxDir)) return $this->errorResult("Directory not found: {$evtxDir}");

		// Collect EVTX files
		$files = glob("{$evtxDir}/*.evtx") ?: [];
		if (!empty($channels)) {
			$files = array_filter($files, fn($f) => in_array(strtolower(basename($f)), $channels, true));
		}
		$files = array_values($files);
		if (empty($files)) return $this->errorResult("No .evtx files found in: {$evtxDir}");

		$ssh  = remnux_ssh($config);
		$rdir = $config->remnuxWorkDir;
		$ssh->run("mkdir -p '{$rdir}'");

		// Transfer all EVTX files to REMnux (using shared path where possible)
		$rEvtxDir = "{$rdir}/evtx_bulk";
		$ssh->run("mkdir -p '{$rEvtxDir}'");
		foreach ($files as $lf) {
			$t = SharedPath::ensureOnREMnux($lf, $config, $ssh, $rEvtxDir);
			// If sftp, file is now at rEvtxDir/basename; if mount, note path
		}

		$rOut = "{$rdir}/evtx_bulk_out.json";

		// Build filter args for evtx_dump (fast Rust tool) or python-evtx
		$ssh->run(<<<BASH
OUTFILE='{$rOut}'
echo '[' > "\$OUTFILE"
FIRST=1
for evtx_file in '{$rEvtxDir}'/*.evtx; do
  [ -f "\$evtx_file" ] || continue
  CHAN=\$(basename "\$evtx_file")
  if command -v evtx_dump &>/dev/null; then
    evtx_dump -o jsonl "\$evtx_file" 2>/dev/null | while IFS= read -r line; do
      [ -n "\$line" ] || continue
      if [ "\$FIRST" = "0" ]; then echo ',' >> "\$OUTFILE"; fi
      echo "\$line" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  d['_channel']='$CHAN'
  print(json.dumps(d))
except: pass
" >> "\$OUTFILE" && FIRST=0
    done
  fi
done
echo ']' >> "\$OUTFILE"
BASH, 180);

		$localOut = "{$case->derivedDir}/evtx_bulk_" . time() . '.json';
		$ssh->copyFrom($rOut, $localOut);
		$ssh->run("rm -rf '{$rEvtxDir}' '{$rOut}'");

		// Parse + filter locally
		$content = file_exists($localOut) ? file_get_contents($localOut) : '';
		$records = json_decode($content, true) ?: [];

		if (empty($records)) {
			// Fallback: run evtx_parse individually per channel then merge here
			$allRecords = [];
			foreach (array_slice($files, 0, 10) as $lf) {
				$stem  = pathinfo($lf, PATHINFO_FILENAME);
				$t     = SharedPath::ensureOnREMnux($lf, $config, $ssh, $rdir);
				$rPath = $t['path'];
				$rJ    = "{$rdir}/{$stem}_tmp.json";
				$ssh->run("if command -v evtx_dump &>/dev/null; then evtx_dump -o jsonl '{$rPath}' > '{$rJ}' 2>/dev/null; fi", 60);
				$lJ = "{$case->derivedDir}/{$stem}_tmp.json";
				$ssh->copyFrom($rJ, $lJ);
				$ssh->run("rm -f '{$rJ}'");
				if ($t['method'] === 'sftp') $ssh->run("rm -f '{$rPath}'");
				if (file_exists($lJ)) {
					foreach (file($lJ, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
						$r = json_decode($line, true);
						if (is_array($r)) { $r['_channel'] = basename($lf); $allRecords[] = $r; }
					}
					unlink($lJ);
				}
			}
			$records = $allRecords;
		}

		// Filter
		$events    = [];
		$eidCounts = [];
		$tsFrom    = $timeFrom !== '' ? strtotime($timeFrom) : 0;
		$tsTo      = $timeTo   !== '' ? strtotime($timeTo) : PHP_INT_MAX;

		foreach ($records as $rec) {
			// Extract common fields from JSON or XML-parsed structure
			$eid  = $rec['Event']['System']['EventID'] ?? null;
			if (is_array($eid)) $eid = $eid['#text'] ?? null;
			$ts   = $rec['Event']['System']['TimeCreated']['#attributes']['SystemTime'] ?? '';
			$xml  = isset($rec['xml']) ? $rec['xml'] : json_encode($rec);

			if ($eid === null && preg_match('/<EventID[^>]*>(\d+)</', $xml, $m)) $eid = (int) $m[1];
			if ($ts  === '' && preg_match('/SystemTime=["\']([^"\']+)/', $xml, $m))  $ts  = $m[1];

			$eidI = (int) $eid;
			$tRec = $ts !== '' ? strtotime($ts) : 0;

			if (!empty($eventIds) && !in_array($eidI, $eventIds, true)) continue;
			if ($tRec > 0 && ($tRec < $tsFrom || $tRec > $tsTo))        continue;
			if ($username  !== '' && !str_contains(strtolower($xml), $username))  continue;
			if ($procName  !== '' && !str_contains(strtolower($xml), $procName))  continue;
			if ($keyword   !== '' && !str_contains(strtolower($xml), $keyword))   continue;

			$eidCounts[$eidI] = ($eidCounts[$eidI] ?? 0) + 1;
			if (count($events) < $maxEvents) $events[] = $rec;
		}

		arsort($eidCounts);

		$result = [
			'files_processed'  => count($files),
			'total_records'    => count($records),
			'matched_events'   => count($events),
			'event_id_summary' => array_slice($eidCounts, 0, 20, true),
			'events'           => array_slice($events, 0, 50),
		];

		$this->writeJson($localOut, $result);

		$evidence = ["evtx_bulk:files={$result['files_processed']}:matched={$result['matched_events']}"];
		foreach (array_slice($eidCounts, 0, 10, true) as $eid => $cnt) $evidence[] = "evtx_bulk:EventID={$eid}:count={$cnt}";

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($events),
			producedFiles:     [$localOut],
			structuredResults: $result,
			evidencePointers:  $evidence,
			stdoutExcerpt:     "EVTX bulk: {$result['files_processed']} files, {$result['total_records']} records, {$result['matched_events']} matched. Top IDs: " . json_encode(array_slice($eidCounts, 0, 5, true)),
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, "ssh:{$config->remnuxHost}", 'evtx_bulk_query'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// pcap_stream_extract
// ─────────────────────────────────────────────────────────────────
final class PcapStreamExtract extends BaseAdapter
{
	public const NAME        = 'pcap_stream_extract';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Extract and reassemble TCP/UDP stream payloads from a PCAP/PCAPNG using tshark --export-objects and follow-stream. Returns full HTTP request/response bodies, file objects transferred over HTTP/SMB/FTP, and raw stream content for C2 analysis. More powerful than pcap_filter for payload recovery.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'pcap_path' => [
						'type'        => 'string',
						'description' => 'Path to PCAP/PCAPNG file (relative to case dir).',
					],
					'mode' => [
						'type'        => 'string',
						'enum'        => ['http_objects', 'stream_follow', 'beaconing'],
						'description' => 'Extraction mode: "http_objects" exports files transferred over HTTP; "stream_follow" reassembles TCP streams to text; "beaconing" analyses inter-packet intervals per destination to detect C2 heartbeats.',
						'default'     => 'http_objects',
					],
					'stream_index' => [
						'type'        => 'integer',
						'description' => 'For mode=stream_follow: TCP stream index to extract (0-based). Use pcap_filter first to identify the stream index.',
					],
					'filter' => [
						'type'        => 'string',
						'description' => 'Wireshark display filter to narrow the PCAP before processing (e.g. "ip.addr==10.0.0.1").',
					],
					'max_streams' => [
						'type'        => 'integer',
						'description' => 'For stream_follow: max number of streams to extract (default: 10).',
						'default'     => 10,
					],
				],
				'required' => ['pcap_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$pcapPath    = $this->resolveFilePath($case, $this->requireParam($params, 'pcap_path'));
		$mode        = $params['mode']         ?? 'http_objects';
		$streamIdx   = $params['stream_index'] ?? null;
		$filter      = $params['filter']       ?? '';
		$maxStreams   = (int) ($params['max_streams'] ?? 10);

		if (!file_exists($pcapPath)) return $this->errorResult("File not found: {$pcapPath}");

		$ssh  = remnux_ssh($config);
		$rdir = $config->remnuxWorkDir;
		$ssh->run("mkdir -p '{$rdir}'");
		$transfer = SharedPath::ensureOnREMnux($pcapPath, $config, $ssh, $rdir);
		$rPcap    = $transfer['path'];
		$stem     = pathinfo($pcapPath, PATHINFO_FILENAME);

		$results  = []; $evidence = []; $producedFiles = [];
		$filterArg = $filter !== '' ? " -Y " . escapeshellarg($filter) : '';

		if ($mode === 'http_objects') {
			// Export HTTP objects (transferred files) to a temp dir
			$rObjDir = "{$rdir}/http_objects_{$stem}";
			$ssh->run("mkdir -p '{$rObjDir}'");
			$r = $ssh->run("tshark -r '{$rPcap}'{$filterArg} --export-objects 'http,{$rObjDir}' 2>/dev/null", 120);

			// List exported objects
			$listing = $ssh->run("ls -la '{$rObjDir}' 2>/dev/null");
			$objects = [];
			foreach (explode("\n", $listing->stdout) as $line) {
				if (preg_match('/(\d+)\s+(\S+.*)$/', $line, $m)) {
					$fname   = trim($m[2]);
					$size    = (int) $m[1];
					$lLocal  = "{$case->derivedDir}/http_obj_{$stem}_" . basename($fname);
					$ssh->copyFrom("{$rObjDir}/{$fname}", $lLocal);
					if (file_exists($lLocal)) {
						$objects[] = ['filename' => $fname, 'size_bytes' => $size, 'sha256' => hash_file('sha256', $lLocal), 'local' => $lLocal];
						$producedFiles[] = $lLocal;
						$evidence[] = "pcap:http_object:{$fname}:sha256=" . hash_file('sha256', $lLocal);
					}
				}
			}
			$ssh->run("rm -rf '{$rObjDir}'");
			$results = ['mode' => 'http_objects', 'objects_exported' => count($objects), 'objects' => $objects];

		} elseif ($mode === 'stream_follow') {
			$streams  = [];
			$idxRange = $streamIdx !== null ? [$streamIdx] : range(0, $maxStreams - 1);
			foreach ($idxRange as $idx) {
				$rOut = "{$rdir}/stream_{$idx}.txt";
				$r    = $ssh->run("tshark -r '{$rPcap}'{$filterArg} -q -z 'follow,tcp,ascii,{$idx}' 2>/dev/null | head -300 > '{$rOut}' 2>/dev/null", 60);
				$lOut = "{$case->derivedDir}/{$stem}_stream_{$idx}.txt";
				$ssh->copyFrom($rOut, $lOut);
				$ssh->run("rm -f '{$rOut}'");
				if (file_exists($lOut) && filesize($lOut) > 50) {
					$content   = mb_substr(file_get_contents($lOut), 0, 8000);
					$streams[] = ['stream_index' => $idx, 'content_preview' => $content];
					$producedFiles[] = $lOut;
					// Flag IOCs in stream
					if (preg_match_all('/https?:\/\/[^\s\'"<>]+/i', $content, $m)) foreach ($m[0] as $u) $evidence[] = 'pcap:stream_url=' . mb_substr($u, 0, 80);
					if (preg_match_all('/[0-9a-f]{32,}/i', $content, $m)) foreach (array_slice($m[0], 0, 5) as $h) $evidence[] = "pcap:stream_hash={$h}";
				} else { break; }
			}
			$results = ['mode' => 'stream_follow', 'streams_extracted' => count($streams), 'streams' => $streams];

		} elseif ($mode === 'beaconing') {
			// Analyse inter-packet timing per destination — detect regular C2 heartbeats
			$rOut = "{$rdir}/beacon_analysis.txt";
			$ssh->run("tshark -r '{$rPcap}'{$filterArg} -T fields -e frame.time_epoch -e ip.dst -e tcp.dstport -E separator='|' 2>/dev/null | sort > '{$rOut}'", 90);
			$lOut = "{$case->derivedDir}/{$stem}_beaconing.txt";
			$ssh->copyFrom($rOut, $lOut); $ssh->run("rm -f '{$rOut}'");

			$intervals = [];
			if (file_exists($lOut)) {
				$lines    = file($lOut, FILE_IGNORE_NEW_LINES) ?: [];
				$byDst    = [];
				foreach ($lines as $line) {
					[$ts, $dst, $dport] = array_pad(explode('|', $line), 3, '');
					if (!$dst) continue;
					$key = "{$dst}:{$dport}";
					$byDst[$key][] = (float) $ts;
				}
				foreach ($byDst as $dst => $times) {
					if (count($times) < 5) continue;
					$diffs = [];
					for ($i = 1; $i < count($times); $i++) $diffs[] = $times[$i] - $times[$i - 1];
					$mean = array_sum($diffs) / count($diffs);
					$stddev = sqrt(array_sum(array_map(fn($d) => ($d - $mean) ** 2, $diffs)) / count($diffs));
					if ($stddev < $mean * 0.15 && $mean > 0) { // CV < 15% = very regular
						$intervals[] = ['destination' => $dst, 'packet_count' => count($times), 'mean_interval_s' => round($mean, 2), 'stddev_s' => round($stddev, 3)];
						$evidence[]  = "pcap:beacon:{$dst}:interval={$mean}s:cv=" . round($stddev / $mean, 3);
					}
				}
				usort($intervals, fn($a, $b) => $a['stddev_s'] <=> $b['stddev_s']);
				$producedFiles[] = $lOut;
			}
			$results = ['mode' => 'beaconing', 'beacon_candidates' => count($intervals), 'candidates' => array_slice($intervals, 0, 20)];
		}

		if ($transfer['method'] === 'sftp') $ssh->run("rm -f '{$rPcap}'");

		$outJson = "{$case->derivedDir}/pcap_stream_{$mode}_{$stem}.json";
		$this->writeJson($outJson, $results);
		$producedFiles[] = $outJson;

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($results),
			producedFiles:     $producedFiles,
			structuredResults: $results,
			evidencePointers:  array_slice($evidence, 0, 30),
			stdoutExcerpt:     "PCAP stream extract [{$mode}]: " . json_encode(array_diff_key($results, ['objects' => 1, 'streams' => 1, 'candidates' => 1])),
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, "ssh:{$config->remnuxHost}", 'pcap_stream_extract'),
		);
	}
}
