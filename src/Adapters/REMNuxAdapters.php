<?php

declare(strict_types=1);

namespace DFIRCopilot\Adapters;

use DFIRCopilot\Case\Workspace;
use DFIRCopilot\Config;
use DFIRCopilot\Executors\ExecResult;
use DFIRCopilot\Executors\SSHExecutor;

// ─────────────────────────────────────────────────────────────────
// Helper: get SSH connection from config
// ─────────────────────────────────────────────────────────────────

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

		if (!file_exists($fp)) {
			return $this->errorResult("File not found: {$fp}");
		}

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;
		$remoteFp  = "{$remoteDir}/" . basename($fp);
		$remoteOut = "{$remoteDir}/" . pathinfo($fp, PATHINFO_FILENAME) . '_strings.txt';

		$ssh->run("mkdir -p {$remoteDir}");
		if (!$ssh->copyTo($fp, $remoteFp)) {
			return $this->errorResult("Failed to copy file to REMnux");
		}

		$cmd    = "strings -n {$min} '{$remoteFp}' > '{$remoteOut}' && strings -n {$min} -el '{$remoteFp}' >> '{$remoteOut}'";
		$result = $ssh->run($cmd, 120);

		$stem     = pathinfo($fp, PATHINFO_FILENAME);
		$localOut = "{$case->derivedDir}/{$stem}_strings.txt";
		$ssh->copyFrom($remoteOut, $localOut);
		$ssh->run("rm -f '{$remoteFp}' '{$remoteOut}'");

		$lineCount = file_exists($localOut) ? count(file($localOut)) : 0;

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           $result->ok,
			producedFiles:     [$localOut],
			structuredResults: ['string_count' => $lineCount, 'output_file' => $localOut],
			evidencePointers:  ["strings:" . basename($fp) . ":lines={$lineCount}"],
			stdoutExcerpt:     "Extracted {$lineCount} strings from " . basename($fp),
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

		if (!file_exists($fp)) {
			return $this->errorResult("File not found: {$fp}");
		}

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;
		$remoteFp  = "{$remoteDir}/" . basename($fp);
		$remoteOut = "{$remoteDir}/" . pathinfo($fp, PATHINFO_FILENAME) . '_yara.txt';

		$ssh->run("mkdir -p {$remoteDir}");
		$ssh->copyTo($fp, $remoteFp);

		$rulesPath = ($rule === 'all') ? '/usr/share/yara-rules' : "/usr/share/yara-rules/{$rule}";
		$cmd       = "yara -r -s '{$rulesPath}' '{$remoteFp}' > '{$remoteOut}' 2>&1 || true";
		$result    = $ssh->run($cmd, 180);

		$stem    = pathinfo($fp, PATHINFO_FILENAME);
		$rawOut  = "{$case->derivedDir}/{$stem}_yara_raw.txt";
		$jsonOut = "{$case->derivedDir}/{$stem}_yara.json";
		$ssh->copyFrom($remoteOut, $rawOut);
		$ssh->run("rm -f '{$remoteFp}' '{$remoteOut}'");

		// Parse matches
		$matches = [];
		if (file_exists($rawOut)) {
			foreach (file($rawOut, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
				if (!str_starts_with($line, 'error')) {
					$parts = explode(' ', $line, 2);
					$matches[] = [
						'rule'   => $parts[0],
						'detail' => $parts[1] ?? '',
					];
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
		$remoteFp  = "{$remoteDir}/" . basename($fp);
		$remoteJson = "{$remoteDir}/" . pathinfo($fp, PATHINFO_FILENAME) . '_capa.json';
		$remoteTxt  = "{$remoteDir}/" . pathinfo($fp, PATHINFO_FILENAME) . '_capa.txt';

		$ssh->run("mkdir -p {$remoteDir}");
		$ssh->copyTo($fp, $remoteFp);

		$cmd    = "capa -j '{$remoteFp}' > '{$remoteJson}' 2>/dev/null || capa '{$remoteFp}' > '{$remoteTxt}' 2>&1";
		$result = $ssh->run($cmd, 300);

		$stem     = pathinfo($fp, PATHINFO_FILENAME);
		$localJson = "{$case->derivedDir}/{$stem}_capa.json";
		$localTxt  = "{$case->derivedDir}/{$stem}_capa.txt";
		$ssh->copyFrom($remoteJson, $localJson);
		$ssh->copyFrom($remoteTxt, $localTxt);
		$ssh->run("rm -f '{$remoteFp}' '{$remoteJson}' '{$remoteTxt}'");

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
// vol3_triage
// ─────────────────────────────────────────────────────────────────

final class Vol3Triage extends BaseAdapter
{
	public const NAME        = 'vol3_triage';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Run Volatility 3 triage pack (pslist, pstree, netscan, cmdline, dlllist) on a memory image.';
	public const TARGET      = 'remnux';

	private const DEFAULT_PLUGINS = [
		'windows.pslist.PsList',
		'windows.pstree.PsTree',
		'windows.netscan.NetScan',
		'windows.cmdline.CmdLine',
		'windows.dlllist.DllList',
	];

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'memory_image' => ['type' => 'string', 'description' => 'Path to memory image (relative to case dir)'],
					'plugins'      => ['type' => 'array', 'items' => ['type' => 'string'], 'description' => 'Plugins to run (default: triage pack)'],
				],
				'required' => ['memory_image'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp      = $this->resolveFilePath($case, $this->requireParam($params, 'memory_image'));
		$plugins = $params['plugins'] ?? self::DEFAULT_PLUGINS;

		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;
		$remoteFp  = "{$remoteDir}/" . basename($fp);

		$ssh->run("mkdir -p {$remoteDir}");

		// Copy (use extended timeout for large images)
		$timeout = filesize($fp) > 500_000_000 ? 600 : 300;
		$ssh->copyTo($fp, $remoteFp);

		$pluginResults = [];
		$producedFiles = [];
		$evidence      = [];

		foreach ($plugins as $plugin) {
			$short     = strtolower(array_slice(explode('.', $plugin), -1)[0]);
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

		// Cleanup vol outputs (keep memory image for potential re-runs)
		$ssh->run("rm -f {$remoteDir}/vol3_*.json {$remoteDir}/vol3_*.txt");

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     $producedFiles,
			structuredResults: $pluginResults,
			evidencePointers:  $evidence,
			stdoutExcerpt:     "Vol3 triage: " . count($plugins) . " plugins run",
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
		$remoteFp  = "{$remoteDir}/" . basename($fp);
		$plasoDb   = "{$remoteDir}/timeline.plaso";
		$remoteOut = "{$remoteDir}/timeline.{$format}";

		$ssh->run("mkdir -p {$remoteDir}");
		$ssh->copyTo($fp, $remoteFp);

		// log2timeline → plaso → psort
		$resultL2t = $ssh->run("log2timeline.py --status_view none '{$plasoDb}' '{$remoteFp}' 2>&1", 600);

		$exportCmd = ($format === 'csv')
			? "psort.py -o l2tcsv -w '{$remoteOut}' '{$plasoDb}' 2>&1"
			: "psort.py -o json_line -w '{$remoteOut}' '{$plasoDb}' 2>&1";
		$resultExport = $ssh->run($exportCmd, 300);

		$localOut = "{$case->timelinesDir}/timeline.{$format}";
		$ssh->copyFrom($remoteOut, $localOut);
		$ssh->run("rm -f '{$plasoDb}' '{$remoteOut}' '{$remoteFp}'");

		$lineCount = file_exists($localOut) ? count(file($localOut)) : 0;

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           $resultL2t->ok || file_exists($localOut),
			producedFiles:     [$localOut],
			structuredResults: ['output_file' => $localOut, 'format' => $format, 'event_count' => $lineCount],
			evidencePointers:  ["timeline:events={$lineCount}"],
			stdoutExcerpt:     "Timeline: {$lineCount} events in {$format}",
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
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Extract network summary from a PCAP: conversations, DNS, HTTP, TLS SNI. Uses tshark on REMnux.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'pcap_path' => ['type' => 'string', 'description' => 'Path to PCAP file (relative to case dir)'],
				],
				'required' => ['pcap_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp = $this->resolveFilePath($case, $this->requireParam($params, 'pcap_path'));
		if (!file_exists($fp)) return $this->errorResult("File not found: {$fp}");

		$ssh       = remnux_ssh($config);
		$remoteDir = $config->remnuxWorkDir;
		$remoteFp  = "{$remoteDir}/" . basename($fp);

		$ssh->run("mkdir -p {$remoteDir}");
		$ssh->copyTo($fp, $remoteFp);

		$results = [];

		// TCP conversations
		$r = $ssh->run("tshark -r '{$remoteFp}' -q -z conv,tcp 2>/dev/null | head -100");
		$results['tcp_conversations'] = $r->stdout;

		// DNS queries
		$r = $ssh->run("tshark -r '{$remoteFp}' -Y 'dns.qry.name' -T fields -e dns.qry.name 2>/dev/null | sort -u");
		$results['dns_queries'] = array_filter(explode("\n", trim($r->stdout)));

		// HTTP hosts + URIs
		$r = $ssh->run("tshark -r '{$remoteFp}' -Y 'http.request' -T fields -e http.host -e http.request.uri 2>/dev/null | head -50");
		$results['http_requests'] = $r->stdout;

		// TLS SNI
		$r = $ssh->run("tshark -r '{$remoteFp}' -Y 'tls.handshake.extensions_server_name' -T fields -e tls.handshake.extensions_server_name 2>/dev/null | sort -u");
		$results['tls_sni'] = array_filter(explode("\n", trim($r->stdout)));

		// capinfos
		$r = $ssh->run("capinfos '{$remoteFp}' 2>/dev/null");
		$results['pcap_info'] = $r->stdout;

		$ssh->run("rm -f '{$remoteFp}'");

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

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: $results,
			evidencePointers:  $evidence,
			stdoutExcerpt:     "PCAP: {$dnsCount} DNS, {$sniCount} TLS SNI",
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, "ssh:{$config->remnuxHost}", 'pcap_summary'),
		);
	}
}