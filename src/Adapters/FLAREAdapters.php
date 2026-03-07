<?php

declare(strict_types=1);

namespace DFIRCopilot\Adapters;

use DFIRCopilot\Case\Workspace;
use DFIRCopilot\Config;
use DFIRCopilot\Executors\ExecResult;
use DFIRCopilot\Executors\WinRMExecutor;

final class PEQuicklook extends BaseAdapter
{
	public const NAME        = 'pe_quicklook';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Extract PE metadata (imports, exports, sections, compile timestamp, signatures) via FLARE-VM WinRM.';
	public const TARGET      = 'flare';

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
						'description' => 'Path to PE file (relative to case dir). Transferred via shared folder.',
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

		// Transfer via shared folder
		$sharedHost = $config->flareSharedHostPath;
		$sharedVM   = $config->flareSharedVMPath;

		if ($sharedHost !== '' && $sharedVM !== '') {
			if (!is_dir($sharedHost)) {
				mkdir($sharedHost, 0755, true);
			}
			copy($fp, "{$sharedHost}/" . basename($fp));
			$vmFile = "{$sharedVM}\\" . basename($fp);
		} else {
			// Assume file is manually placed at C:\dfirbus
			$vmFile = "C:\\dfirbus\\" . basename($fp);
		}

		$winrm = WinRMExecutor::fromConfig($config);

		// PowerShell script using .NET reflection — works on any Windows
		$ps = <<<PS
\$ErrorActionPreference = 'SilentlyContinue'
\$filePath = '{$vmFile}'
\$result = @{}

\$fileInfo = Get-Item \$filePath
\$result['FileName'] = \$fileInfo.Name
\$result['SizeBytes'] = \$fileInfo.Length
\$result['LastWriteTime'] = \$fileInfo.LastWriteTime.ToString('o')

try {
    \$bytes = [System.IO.File]::ReadAllBytes(\$filePath)
    if (\$bytes[0] -eq 0x4D -and \$bytes[1] -eq 0x5A) {
        \$result['IsPE'] = \$true
        \$peOffset = [BitConverter]::ToInt32(\$bytes, 0x3C)
        \$machine = [BitConverter]::ToUInt16(\$bytes, \$peOffset + 4)
        \$result['Machine'] = switch (\$machine) {
            0x14c { 'x86' }
            0x8664 { 'x64' }
            default { "0x\$(\$machine.ToString('X4'))" }
        }
        \$timestamp = [BitConverter]::ToUInt32(\$bytes, \$peOffset + 8)
        \$epoch = [datetime]'1970-01-01'
        \$result['CompileTimestamp'] = \$epoch.AddSeconds(\$timestamp).ToString('o')
        \$numSections = [BitConverter]::ToUInt16(\$bytes, \$peOffset + 6)
        \$result['NumberOfSections'] = \$numSections
        \$optMagic = [BitConverter]::ToUInt16(\$bytes, \$peOffset + 24)
        \$result['Is64Bit'] = (\$optMagic -eq 0x20B)
        \$subsystemOffset = if (\$optMagic -eq 0x20B) { \$peOffset + 92 } else { \$peOffset + 68 }
        \$subsystem = [BitConverter]::ToUInt16(\$bytes, \$subsystemOffset)
        \$result['Subsystem'] = switch (\$subsystem) {
            2 { 'GUI' }
            3 { 'Console' }
            default { \$subsystem }
        }
    } else {
        \$result['IsPE'] = \$false
    }
} catch {
    \$result['Error'] = \$_.Exception.Message
}

try {
    \$sig = Get-AuthenticodeSignature \$filePath
    \$result['SignatureStatus'] = \$sig.Status.ToString()
    if (\$sig.SignerCertificate) {
        \$result['Signer'] = \$sig.SignerCertificate.Subject
        \$result['SignerThumbprint'] = \$sig.SignerCertificate.Thumbprint
    }
} catch {}

\$result | ConvertTo-Json -Depth 3
PS;

		$result = $winrm->run($ps, 60);

		$peInfo = [];
		if ($result->ok && trim($result->stdout) !== '') {
			$decoded = json_decode($result->stdout, true);
			$peInfo  = is_array($decoded) ? $decoded : ['raw_output' => mb_substr($result->stdout, 0, 3000)];
		}

		$stem    = pathinfo($fp, PATHINFO_FILENAME);
		$outPath = "{$case->derivedDir}/{$stem}_pe_quicklook.json";
		$this->writeJson($outPath, $peInfo);

		$evidence = [];
		if (isset($peInfo['CompileTimestamp'])) {
			$evidence[] = "pe:" . basename($fp) . ":compile={$peInfo['CompileTimestamp']}";
		}
		if (isset($peInfo['Signer'])) {
			$evidence[] = "pe:" . basename($fp) . ":signer=" . mb_substr($peInfo['Signer'], 0, 80);
		}
		if (isset($peInfo['Machine'])) {
			$evidence[] = "pe:" . basename($fp) . ":arch={$peInfo['Machine']}";
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [$outPath],
			structuredResults: $peInfo,
			evidencePointers:  $evidence,
			stdoutExcerpt:     json_encode($peInfo, JSON_PRETTY_PRINT),
			stderrExcerpt:     mb_substr($result->stderr, 0, 500),
			execResult:        $result,
		);
	}
}