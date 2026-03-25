<?php

declare(strict_types=1);

namespace DFIRCopilot\Adapters;

use DFIRCopilot\Case\Workspace;
use DFIRCopilot\Config;
use DFIRCopilot\Executors\ExecResult;
use DFIRCopilot\Executors\SSHExecutor;
use DFIRCopilot\Executors\SharedPath;

function disk_ssh(Config $config): SSHExecutor
{
	return SSHExecutor::fromConfig($config);
}

/**
 * Auto-detect the primary partition offset (sectors) via mmls.
 * Returns the largest NTFS partition (best guess for Windows OS volume).
 */
function disk_detect_partition(SSHExecutor $ssh, string $remoteFp): array
{
	$ext     = strtolower(pathinfo($remoteFp, PATHINFO_EXTENSION));
	$ewfFlag = in_array($ext, ['e01', 'ex01', 'l01', 'lx01'], true) ? '-i ewf' : '';

	$r    = $ssh->run("mmls {$ewfFlag} '{$remoteFp}' 2>&1");
	$ntfs = [];
	$any  = [];

	foreach (explode("\n", $r->stdout) as $line) {
		$line = trim($line);
		// e.g.: "002:  000:000   128   1048703   1048576   NTFS / exFAT (0x07)"
		if (!preg_match('/^\d{3}:\s+\d{3}:\d{3}\s+(\d+)\s+\d+\s+(\d+)\s+(.+)$/', $line, $m)) {
			continue;
		}
		$desc = trim($m[3]);
		$row  = ['start' => (int) $m[1], 'length' => (int) $m[2], 'desc' => $desc];

		if (stripos($desc, 'ntfs') !== false || str_contains($desc, '0x07')) {
			$ntfs[] = $row;
		} else {
			$any[] = $row;
		}
	}

	$candidates = !empty($ntfs) ? $ntfs : $any;
	usort($candidates, fn($a, $b) => $b['length'] <=> $a['length']);
	$best = $candidates[0] ?? ['start' => 0, 'desc' => 'unknown'];

	return [
		'offset'   => $best['start'],
		'ewf_flag' => $ewfFlag,
		'mmls_out' => mb_substr($r->stdout, 0, 2000),
	];
}

// ─────────────────────────────────────────────────────────────────
// disk_timeline
// ─────────────────────────────────────────────────────────────────

/**
 * MAC-time filesystem timeline using TSK fls + mactime.
 * Does NOT require log2timeline/plaso.
 * Answer: "what changed on the system on DATE?"
 */
final class DiskTimeline extends BaseAdapter
{
	public const NAME        = 'disk_timeline';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Build a MAC-time filesystem timeline from a disk image (E01, raw) using The Sleuth Kit (fls + mactime). Does NOT require log2timeline. Use date_filter (YYYY-MM-DD) to focus on a specific date — e.g. "2026-03-19" to find all files created/modified/accessed that day. The essential first step for any disk image investigation.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'image_path' => [
						'type'        => 'string',
						'description' => 'Path to disk image (E01, raw, img, dd) relative to case dir.',
					],
					'date_filter' => [
						'type'        => 'string',
						'description' => 'Filter to a specific date: YYYY-MM-DD (e.g. "2026-03-19"). Omit for all events (capped at 5000).',
						'default'     => '',
					],
					'partition_offset' => [
						'type'        => 'integer',
						'description' => 'Partition start offset in sectors. Auto-detected from mmls if omitted.',
					],
				],
				'required' => ['image_path'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp           = $this->resolveFilePath($case, $this->requireParam($params, 'image_path'));
		$dateFilter   = trim($params['date_filter'] ?? '');
		$manualOffset = isset($params['partition_offset']) ? (int) $params['partition_offset'] : null;

		if (!file_exists($fp)) return $this->errorResult("Image not found: {$fp}");

		$ssh       = disk_ssh($config);
		$remoteDir = $config->remnuxWorkDir;
		$ssh->run("mkdir -p '{$remoteDir}'");

		$transfer = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp = $transfer['path'];

		$part    = disk_detect_partition($ssh, $remoteFp);
		$offset  = $manualOffset ?? $part['offset'];
		$ewfFlag = $part['ewf_flag'];

		$bodyfile = "{$remoteDir}/dfircop_body.txt";
		$tlOut    = "{$remoteDir}/dfircop_tl.csv";

		// Build bodyfile — can take many minutes on large images
		$ssh->run(
			"fls -r -m '/' {$ewfFlag} -f ntfs -o {$offset} '{$remoteFp}' > '{$bodyfile}' 2>/dev/null",
			1800,
		);

		// Mactime filter
		if ($dateFilter !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $dateFilter)) {
			$mac = $ssh->run("mactime -b '{$bodyfile}' -d {$dateFilter} 2>/dev/null | sort", 300);
		} else {
			$mac = $ssh->run("mactime -b '{$bodyfile}' 2>/dev/null | sort | head -5000", 300);
		}

		// Write and retrieve
		$ssh->run("printf '%s' " . escapeshellarg($mac->stdout) . " > '{$tlOut}'");
		$suffix   = $dateFilter !== '' ? "_{$dateFilter}" : '';
		$localOut = "{$case->derivedDir}/disk_timeline{$suffix}.csv";
		$ssh->copyFrom($tlOut, $localOut);
		$ssh->run("rm -f '{$bodyfile}' '{$tlOut}'");
		if ($transfer['method'] === 'sftp') $ssh->run("rm -f '{$remoteFp}'");

		$content = file_exists($localOut) ? file_get_contents($localOut) : '';
		$lines   = array_filter(explode("\n", $content));
		$count   = count($lines);

		$evidence = [];
		$sample   = [];
		foreach (array_slice($lines, 0, 300) as $l) {
			$sample[] = mb_substr($l, 0, 200);
			if (preg_match('/\.(exe|dll|bat|ps1|vbs|js|cmd|scr|sys|drv|lnk|tmp)\b/i', $l)) {
				$evidence[] = 'timeline:exec:' . mb_substr($l, 0, 150);
			}
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           $count > 0,
			producedFiles:     [$localOut],
			structuredResults: [
				'date_filter'  => $dateFilter ?: 'all',
				'event_count'  => $count,
				'offset'       => $offset,
				'sample_lines' => array_slice($sample, 0, 50),
			],
			evidencePointers:  array_slice($evidence, 0, 50),
			stdoutExcerpt:     "Disk timeline (" . ($dateFilter ?: 'all') . "): {$count} events via {$transfer['method']}",
			stderrExcerpt:     mb_substr($part['mmls_out'], 0, 300),
			execResult:        new ExecResult(0, '', '', 0, "ssh:{$config->remnuxHost}", 'disk_timeline'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// mft_search
// ─────────────────────────────────────────────────────────────────

final class MftSearch extends BaseAdapter
{
	public const NAME        = 'mft_search';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Search a disk image (E01/raw) for files matching a name pattern using TSK fls + grep. Faster than a full timeline — use this to locate specific files (e.g. "*.ps1", "mimikatz", "SYSTEM", ".pf") before extracting them.';
	public const TARGET      = 'remnux';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'image_path' => [
						'type'        => 'string',
						'description' => 'Path to disk image (relative to case dir).',
					],
					'pattern' => [
						'type'        => 'string',
						'description' => 'Search pattern (case-insensitive grep). E.g. "\\.ps1$", "SYSTEM$", "\\.pf$", "mimikatz".',
					],
					'partition_offset' => [
						'type'        => 'integer',
						'description' => 'Partition offset in sectors (auto-detected if omitted).',
					],
				],
				'required' => ['image_path', 'pattern'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$fp      = $this->resolveFilePath($case, $this->requireParam($params, 'image_path'));
		$pattern = $this->requireParam($params, 'pattern');
		$manualOffset = isset($params['partition_offset']) ? (int) $params['partition_offset'] : null;

		if (!file_exists($fp)) return $this->errorResult("Image not found: {$fp}");

		$ssh       = disk_ssh($config);
		$remoteDir = $config->remnuxWorkDir;
		$ssh->run("mkdir -p '{$remoteDir}'");

		$transfer = SharedPath::ensureOnREMnux($fp, $config, $ssh, $remoteDir);
		$remoteFp = $transfer['path'];

		$part    = disk_detect_partition($ssh, $remoteFp);
		$offset  = $manualOffset ?? $part['offset'];
		$ewfFlag = $part['ewf_flag'];

		$r = $ssh->run(
			"fls -r {$ewfFlag} -o {$offset} '{$remoteFp}' 2>/dev/null | grep -i " . escapeshellarg($pattern) . " | head -500",
			900,
		);

		if ($transfer['method'] === 'sftp') $ssh->run("rm -f '{$remoteFp}'");

		$rawLines = array_filter(array_map('trim', explode("\n", $r->stdout)));
		$entries  = [];
		$evidence = [];

		foreach ($rawLines as $line) {
			// Format: "r/r 1234-128-1:   Windows/Prefetch/CMD.EXE-ABC.pf"
			if (preg_match('/^([drv\/\-]+)\s+([\w\-]+):\s+(.+)$/', $line, $m)) {
				$entries[] = [
					'type'  => trim($m[1]),
					'inode' => trim($m[2]),
					'path'  => trim($m[3]),
				];
				$evidence[] = "mft:match:" . trim($m[3]);
			}
		}

		$stem    = preg_replace('/[^a-z0-9_]/', '_', strtolower($pattern));
		$outPath = "{$case->derivedDir}/mft_search_{$stem}.json";
		$this->writeJson($outPath, $entries);

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($entries),
			producedFiles:     [$outPath],
			structuredResults: ['pattern' => $pattern, 'match_count' => count($entries), 'matches' => $entries],
			evidencePointers:  array_slice($evidence, 0, 50),
			stdoutExcerpt:     "MFT search '{$pattern}': " . count($entries) . " matches",
			stderrExcerpt:     mb_substr($r->stderr, 0, 300),
			execResult:        new ExecResult($r->exitCode, $r->stdout, $r->stderr, 0, "ssh:{$config->remnuxHost}", 'mft_search'),
		);
	}
}

// ─────────────────────────────────────────────────────────────────
// registry_parse
// ─────────────────────────────────────────────────────────────────

/**
 * Extract and parse Windows registry hives from a disk image (or directly).
 * Uses icat (TSK) for extraction and regripper for analysis.
 * Targets: SYSTEM (services, USB, last shutdown), SOFTWARE (installed apps, run keys),
 * SAM (user accounts), NTUSER.DAT (user activity, MRU).
 */
final class RegistryParse extends BaseAdapter
{
	public const NAME        = 'registry_parse';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Extract and analyse Windows registry hives from a disk image (E01/raw) using icat + regripper. Supports SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER hives. Reveals persistence mechanisms, user accounts, installed software, USB history, and recent activity.';
	public const TARGET      = 'remnux';

	private const HIVE_PATHS = [
		'SYSTEM'   => 'Windows/System32/config/SYSTEM$',
		'SOFTWARE' => 'Windows/System32/config/SOFTWARE$',
		'SAM'      => 'Windows/System32/config/SAM$',
		'SECURITY' => 'Windows/System32/config/SECURITY$',
		'NTUSER'   => 'NTUSER\.DAT$',
	];

	private const RIP_PROFILES = [
		'SYSTEM'   => 'system',
		'SOFTWARE' => 'software',
		'SAM'      => 'sam',
		'SECURITY' => 'security',
		'NTUSER'   => 'ntuser',
	];

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'image_path' => [
						'type'        => 'string',
						'description' => 'Path to disk image (E01/raw) to extract hives from. One of image_path or hive_path is required.',
					],
					'hive_path' => [
						'type'        => 'string',
						'description' => 'Path to an already-extracted registry hive file. Use instead of image_path if the hive is already on disk.',
					],
					'hive_name' => [
						'type'        => 'string',
						'enum'        => ['SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY', 'NTUSER', 'all'],
						'description' => 'Which hive(s) to parse (default: SYSTEM). Use "all" for all standard hives.',
						'default'     => 'SYSTEM',
					],
					'partition_offset' => [
						'type'        => 'integer',
						'description' => 'Partition offset in sectors (auto-detected if omitted).',
					],
				],
				'required' => [],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$hiveName = strtoupper($params['hive_name'] ?? 'SYSTEM');
		$rawHive  = isset($params['hive_path']) ? $this->resolveFilePath($case, $params['hive_path']) : '';
		$imgPath  = isset($params['image_path']) ? $this->resolveFilePath($case, $params['image_path']) : '';

		if ($rawHive === '' && $imgPath === '') {
			return $this->errorResult('Provide either image_path or hive_path.');
		}

		$ssh       = disk_ssh($config);
		$remoteDir = $config->remnuxWorkDir;
		$ssh->run("mkdir -p '{$remoteDir}'");

		// ── Path A: direct hive file provided ────────────────────
		if ($rawHive !== '' && file_exists($rawHive)) {
			return $this->parseHiveFile($ssh, $remoteDir, $rawHive, $hiveName, $case, $config);
		}

		// ── Path B: extract from disk image ──────────────────────
		if (!file_exists($imgPath)) return $this->errorResult("Image not found: {$imgPath}");

		$transfer = SharedPath::ensureOnREMnux($imgPath, $config, $ssh, $remoteDir);
		$remoteFp = $transfer['path'];

		$part    = disk_detect_partition($ssh, $remoteFp);
		$offset  = isset($params['partition_offset']) ? (int) $params['partition_offset'] : $part['offset'];
		$ewfFlag = $part['ewf_flag'];

		$hiveNames = $hiveName === 'all' ? array_keys(self::HIVE_PATHS) : [$hiveName];
		$allResults = [];
		$allFiles   = [];
		$allEvidence = [];

		foreach ($hiveNames as $hv) {
			$grepPattern = self::HIVE_PATHS[$hv] ?? null;
			if ($grepPattern === null) continue;

			// Find inode(s)
			$r = $ssh->run(
				"fls -r {$ewfFlag} -o {$offset} '{$remoteFp}' 2>/dev/null | grep -E " . escapeshellarg($grepPattern),
				900,
			);

			foreach (array_filter(array_map('trim', explode("\n", $r->stdout))) as $line) {
				if (!preg_match('/^[rv\/\-]+\s+([\w\-]+):\s+(.+)$/', $line, $m)) continue;
				$inode    = trim($m[1]);
				$filePath = trim($m[2]);
				$basename = basename($filePath);

				$remoteHive = "{$remoteDir}/reg_{$basename}";
				$ssh->run("icat {$ewfFlag} -o {$offset} '{$remoteFp}' {$inode} > '{$remoteHive}' 2>/dev/null", 60);

				$localHive = "{$case->derivedDir}/reg_{$basename}";
				$ssh->copyFrom($remoteHive, $localHive);
				$ssh->run("rm -f '{$remoteHive}'");

				if (!file_exists($localHive) || filesize($localHive) === 0) continue;

				$ripResult = $this->runRegripper($ssh, $remoteDir, $localHive, $hv, $config, $case);
				$allResults[$basename] = $ripResult['text'];
				$allFiles[]            = $ripResult['out_file'];
				$allEvidence[]         = "registry:{$hv}:{$basename}";
			}
		}

		if ($transfer['method'] === 'sftp') $ssh->run("rm -f '{$remoteFp}'");

		$summary = "Parsed " . count($allResults) . " hive(s): " . implode(', ', array_keys($allResults));

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($allResults),
			producedFiles:     $allFiles,
			structuredResults: ['hive_results' => $allResults, 'hives_parsed' => array_keys($allResults)],
			evidencePointers:  $allEvidence,
			stdoutExcerpt:     $summary,
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, "ssh:{$config->remnuxHost}", 'registry_parse'),
		);
	}

	private function parseHiveFile(
		SSHExecutor $ssh,
		string $remoteDir,
		string $localHive,
		string $hiveName,
		Workspace $case,
		Config $config,
	): AdapterResult {
		$r      = $this->runRegripper($ssh, $remoteDir, $localHive, $hiveName, $config, $case);
		$stem   = pathinfo($localHive, PATHINFO_FILENAME);
		return new AdapterResult(
			adapterName:       self::NAME,
			success:           $r['text'] !== '',
			producedFiles:     [$r['out_file']],
			structuredResults: ['hive_results' => [$stem => $r['text']]],
			evidencePointers:  ["registry:{$hiveName}:{$stem}"],
			stdoutExcerpt:     mb_substr($r['text'], 0, 1000),
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, "ssh:{$config->remnuxHost}", 'registry_parse'),
		);
	}

	private function runRegripper(
		SSHExecutor $ssh,
		string $remoteDir,
		string $localHive,
		string $hiveName,
		Config $config,
		Workspace $case,
	): array {
		$remoteHive = "{$remoteDir}/reg_rip_tmp";
		$ssh->copyTo($localHive, $remoteHive);

		$profile   = self::RIP_PROFILES[$hiveName] ?? 'ntuser';
		$remoteOut = "{$remoteDir}/rip_out.txt";

		// rip.pl is regripper's main script on REMnux
		$ripCmd = "rip.pl -r '{$remoteHive}' -f {$profile} > '{$remoteOut}' 2>/dev/null"
			. " || regripper -r '{$remoteHive}' -f {$profile} > '{$remoteOut}' 2>/dev/null";
		$ssh->run($ripCmd, 60);

		$stem    = pathinfo($localHive, PATHINFO_FILENAME);
		$outFile = "{$case->derivedDir}/regripper_{$stem}.txt";
		$ssh->copyFrom($remoteOut, $outFile);
		$ssh->run("rm -f '{$remoteHive}' '{$remoteOut}'");

		$text = file_exists($outFile) ? mb_substr(file_get_contents($outFile), 0, 8000) : '';
		return ['text' => $text, 'out_file' => $outFile];
	}
}

// ─────────────────────────────────────────────────────────────────
// prefetch_parse
// ─────────────────────────────────────────────────────────────────

/**
 * Extract and parse Windows Prefetch (.pf) files from a disk image or directory.
 * Prefetch files record execution history: what ran, when, how many times.
 * Use date_filter to focus on executions from a specific day.
 */
final class PrefetchParse extends BaseAdapter
{
	public const NAME        = 'prefetch_parse';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Extract and parse Windows Prefetch (.pf) files from a disk image (E01/raw) or local directory. Returns execution history: executable name, last run time, run count, referenced files. Use date_filter (YYYY-MM-DD) to focus on a specific day.';
	public const TARGET      = 'remnux';

	// Inline Python to parse prefetch binary  (covers Win 10/11 v30 and Win 7 v23)
	private const PF_PARSER = <<<'PY'
import struct, sys, os, json, glob

def parse_pf(path):
    try:
        with open(path,'rb') as f: data=f.read(300)
        if len(data)<84 or data[4:8]!=b'SCCA': return None
        version=struct.unpack_from('<I',data,0)[0]
        exe=data[16:76].decode('utf-16-le',errors='replace').rstrip('\x00')
        pf_hash=struct.unpack_from('<I',data,76)[0]
        run_count,last_run=0,None
        if version==30:
            with open(path,'rb') as f: d2=f.read(256)
            if len(d2)>=212:
                run_count=struct.unpack_from('<I',d2,208)[0]
                ts=struct.unpack_from('<Q',d2,128)[0]
                if ts>0:
                    import datetime
                    epoch=datetime.datetime(1601,1,1)
                    last_run=(epoch+datetime.timedelta(microseconds=ts//10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        elif version==23:
            with open(path,'rb') as f: d2=f.read(160)
            if len(d2)>=160:
                run_count=struct.unpack_from('<I',d2,152)[0]
                ts=struct.unpack_from('<Q',d2,120)[0]
                if ts>0:
                    import datetime
                    epoch=datetime.datetime(1601,1,1)
                    last_run=(epoch+datetime.timedelta(microseconds=ts//10)).strftime('%Y-%m-%dT%H:%M:%SZ')
        mtime=datetime.datetime.utcfromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%dT%H:%M:%SZ') if 'datetime' in dir() else None
        return {'file':os.path.basename(path),'exe':exe,'hash':hex(pf_hash),'version':version,'run_count':run_count,'last_run_embedded':last_run,'file_mtime':mtime}
    except Exception as e:
        return {'file':os.path.basename(path),'error':str(e)}

path=sys.argv[1]
results=[]
if os.path.isdir(path):
    for f in glob.glob(os.path.join(path,'*.pf'))[:100]:
        r=parse_pf(f)
        if r: results.append(r)
else:
    r=parse_pf(path)
    if r: results.append(r)
results.sort(key=lambda x:(x.get('last_run_embedded') or x.get('file_mtime') or ''),reverse=True)
print(json.dumps(results,indent=2))
PY;

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'image_path' => [
						'type'        => 'string',
						'description' => 'Disk image (E01/raw) to extract Prefetch files from.',
					],
					'file_path' => [
						'type'        => 'string',
						'description' => 'Path to an already-extracted .pf file or a directory containing .pf files.',
					],
					'date_filter' => [
						'type'        => 'string',
						'description' => 'Show only prefetch entries whose file modification time matches YYYY-MM-DD.',
						'default'     => '',
					],
					'partition_offset' => [
						'type'        => 'integer',
						'description' => 'Partition offset in sectors (auto-detected if omitted).',
					],
				],
				'required' => [],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$imgPath    = isset($params['image_path']) ? $this->resolveFilePath($case, $params['image_path']) : '';
		$filePath   = isset($params['file_path'])  ? $this->resolveFilePath($case, $params['file_path'])  : '';
		$dateFilter = trim($params['date_filter'] ?? '');

		if ($imgPath === '' && $filePath === '') {
			return $this->errorResult('Provide either image_path or file_path.');
		}

		$ssh       = disk_ssh($config);
		$remoteDir = $config->remnuxWorkDir;
		$ssh->run("mkdir -p '{$remoteDir}'");

		// ── If file/dir already extracted, parse directly via REMnux ──
		if ($filePath !== '' && file_exists($filePath)) {
			return $this->parsePfFiles($ssh, $remoteDir, [$filePath], $dateFilter, $case, $config);
		}

		// ── Extract .pf files from disk image ──────────────────────
		if (!file_exists($imgPath)) return $this->errorResult("Image not found: {$imgPath}");

		$transfer = SharedPath::ensureOnREMnux($imgPath, $config, $ssh, $remoteDir);
		$remoteFp = $transfer['path'];

		$part    = disk_detect_partition($ssh, $remoteFp);
		$offset  = isset($params['partition_offset']) ? (int) $params['partition_offset'] : $part['offset'];
		$ewfFlag = $part['ewf_flag'];

		// Find all .pf files
		$r = $ssh->run(
			"fls -r {$ewfFlag} -o {$offset} '{$remoteFp}' 2>/dev/null | grep -i '\\.pf$' | head -200",
			900,
		);

		$pfDir = "{$case->derivedDir}/prefetch";
		if (!is_dir($pfDir)) mkdir($pfDir, 0755, true);
		$localPfFiles = [];

		foreach (array_filter(array_map('trim', explode("\n", $r->stdout))) as $line) {
			if (!preg_match('/^[rv\/\-]+\s+([\w\-]+):\s+(.+)$/', $line, $m)) continue;
			$inode    = trim($m[1]);
			$pfName   = basename(trim($m[2]));
			$remotePf = "{$remoteDir}/{$pfName}";
			$localPf  = "{$pfDir}/{$pfName}";

			$ssh->run("icat {$ewfFlag} -o {$offset} '{$remoteFp}' {$inode} > '{$remotePf}' 2>/dev/null", 30);
			$ssh->copyFrom($remotePf, $localPf);
			$ssh->run("rm -f '{$remotePf}'");

			if (file_exists($localPf) && filesize($localPf) > 0) {
				$localPfFiles[] = $localPf;
			}
		}

		if ($transfer['method'] === 'sftp') $ssh->run("rm -f '{$remoteFp}'");

		return $this->parsePfFiles($ssh, $remoteDir, [$pfDir], $dateFilter, $case, $config);
	}

	private function parsePfFiles(
		SSHExecutor $ssh,
		string $remoteDir,
		array $localPaths,
		string $dateFilter,
		Workspace $case,
		Config $config,
	): AdapterResult {
		// Upload inline parser and run
		$parserRemote = "{$remoteDir}/dfircop_pfparse.py";
		$ssh->run("cat > '{$parserRemote}' << 'PYEOF'\n" . self::PF_PARSER . "\nPYEOF");

		$results  = [];
		$evidence = [];

		foreach ($localPaths as $lp) {
			if (!file_exists($lp)) continue;

			$remoteLp = "{$remoteDir}/pf_target";
			if (is_dir($lp)) {
				$ssh->run("mkdir -p '{$remoteLp}'");
				foreach (glob("{$lp}/*.pf") ?: [] as $f) {
					$ssh->copyTo($f, "{$remoteLp}/" . basename($f));
				}
			} else {
				$ssh->copyTo($lp, $remoteLp);
			}

			$r    = $ssh->run("python3 '{$parserRemote}' '{$remoteLp}' 2>/dev/null", 60);
			$data = json_decode($r->stdout, true);

			if (is_array($data)) {
				foreach ($data as $entry) {
					if ($dateFilter !== '' && !$this->matchesDate($entry, $dateFilter)) continue;
					$results[] = $entry;
					if (!empty($entry['exe'])) {
						$evidence[] = "prefetch:{$entry['exe']}:" . ($entry['last_run_embedded'] ?? $entry['file_mtime'] ?? '?');
					}
				}
			}

			$ssh->run("rm -rf '{$remoteLp}'");
		}

		$ssh->run("rm -f '{$parserRemote}'");

		$outPath = "{$case->derivedDir}/prefetch_summary.json";
		$this->writeJson($outPath, $results);

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           !empty($results),
			producedFiles:     [$outPath],
			structuredResults: ['count' => count($results), 'date_filter' => $dateFilter ?: 'all', 'entries' => $results],
			evidencePointers:  array_slice($evidence, 0, 50),
			stdoutExcerpt:     "Prefetch: " . count($results) . " entries" . ($dateFilter ? " (filtered: {$dateFilter})" : ''),
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, "ssh:{$config->remnuxHost}", 'prefetch_parse'),
		);
	}

	private function matchesDate(array $entry, string $date): bool
	{
		foreach (['last_run_embedded', 'file_mtime'] as $field) {
			if (isset($entry[$field]) && str_starts_with((string) $entry[$field], $date)) {
				return true;
			}
		}
		return false;
	}
}
