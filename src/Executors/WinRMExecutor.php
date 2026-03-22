<?php

declare(strict_types=1);

namespace DFIRCopilot\Executors;

use DFIRCopilot\Config;

/**
 * Runs PowerShell commands on FLARE-VM via WinRM (HTTP + Basic auth).
 *
 * This is a minimal WinRM client using native curl — no dependencies.
 * Works for CTF/lab use on a host-only network.
 *
 * WinRM uses SOAP/XML over HTTP. We construct the minimum envelope needed
 * to run a PowerShell command and capture output.
 */
final class WinRMExecutor
{
	private readonly string $endpoint;

	public function __construct(
		private readonly string $host,
		private readonly string $user,
		private readonly string $password,
		private readonly int    $port = 5985,
		private readonly bool   $useSsl = false,
	) {
		$proto = $useSsl ? 'https' : 'http';
		$this->endpoint = "{$proto}://{$host}:{$port}/wsman";
	}

	public static function fromConfig(Config $cfg): self
	{
		return new self(
			host:     $cfg->flareHost,
			user:     $cfg->flareUser,
			password: $cfg->flarePassword,
			port:     $cfg->flareWinRMPort,
		);
	}

	// ── Command execution ────────────────────────────────────────

	public function run(string $psCommand, int $timeout = 300): ExecResult
	{
		$start = hrtime(true);

		try {
			// Step 1: Create a shell
			$shellId = $this->createShell();
			if ($shellId === null) {
				return $this->errorResult('Failed to create WinRM shell', $psCommand, $start);
			}

			// Step 2: Execute command
			// Wrap in powershell -EncodedCommand for safety
			$encoded = base64_encode(mb_convert_encoding($psCommand, 'UTF-16LE', 'UTF-8'));
			$commandId = $this->executeCommand($shellId, "powershell -EncodedCommand {$encoded}");
			if ($commandId === null) {
				$this->deleteShell($shellId);
				return $this->errorResult('Failed to execute command', $psCommand, $start);
			}

			// Step 3: Receive output
			[$stdout, $stderr, $exitCode] = $this->receiveOutput($shellId, $commandId, $timeout);

			// Step 4: Cleanup
			$this->deleteShell($shellId);

			$elapsed = (hrtime(true) - $start) / 1e9;

			return new ExecResult(
				exitCode: $exitCode,
				stdout: $stdout,
				stderr: $stderr,
				durationSeconds: $elapsed,
				executor: "winrm:{$this->host}",
				command: mb_substr($psCommand, 0, 200),
			);
		} catch (\Throwable $e) {
			return $this->errorResult("WinRM error: {$e->getMessage()}", $psCommand, $start);
		}
	}

	public function testConnection(): bool
	{
		try {
			$r = $this->run("Write-Output 'ok'", 15);
			return $r->ok && str_contains($r->stdout, 'ok');
		} catch (\Throwable) {
			return false;
		}
	}

	// ── WinRM SOAP plumbing ──────────────────────────────────────

	private function createShell(): ?string
	{
		$body = <<<'XML'
        <env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                      xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                      xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
                      xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
                      xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd">
          <env:Header>
            <a:To>%ENDPOINT%</a:To>
            <a:MessageID>uuid:%MSGID%</a:MessageID>
            <w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
            <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
            <a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>
            <w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
            <w:OperationTimeout>PT60S</w:OperationTimeout>
            <w:OptionSet>
              <w:Option Name="WINRS_NOPROFILE">TRUE</w:Option>
              <w:Option Name="WINRS_CODEPAGE">65001</w:Option>
            </w:OptionSet>
          </env:Header>
          <env:Body>
            <rsp:Shell>
              <rsp:InputStreams>stdin</rsp:InputStreams>
              <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
            </rsp:Shell>
          </env:Body>
        </env:Envelope>
        XML;

		$body = str_replace('%ENDPOINT%', htmlspecialchars($this->endpoint), $body);
		$body = str_replace('%MSGID%', $this->uuid(), $body);
		$response = $this->soapRequest($body);

		if ($response === null) return null;

		// Extract ShellId from response
		if (preg_match('/<w:Selector Name="ShellId">([^<]+)</', $response, $m)) {
			return $m[1];
		}

		return null;
	}

	private function executeCommand(string $shellId, string $command): ?string
	{
		$escapedCmd = htmlspecialchars($command);
		$body = <<<XML
        <env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                      xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                      xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
                      xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
          <env:Header>
            <a:To>{$this->endpoint}</a:To>
            <a:MessageID>uuid:{$this->uuid()}</a:MessageID>
            <w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
            <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
            <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>
            <w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
            <w:OperationTimeout>PT60S</w:OperationTimeout>
            <w:SelectorSet>
              <w:Selector Name="ShellId">{$shellId}</w:Selector>
            </w:SelectorSet>
          </env:Header>
          <env:Body>
            <rsp:CommandLine>
              <rsp:Command>{$escapedCmd}</rsp:Command>
            </rsp:CommandLine>
          </env:Body>
        </env:Envelope>
        XML;

		$response = $this->soapRequest($body);
		if ($response === null) return null;

		if (preg_match('/<rsp:CommandId>([^<]+)</', $response, $m)) {
			return $m[1];
		}

		return null;
	}

	private function receiveOutput(string $shellId, string $commandId, int $timeout): array
	{
		$stdout   = '';
		$stderr   = '';
		$exitCode = -1;
		$deadline = time() + $timeout;

		while (time() < $deadline) {
			$body = <<<XML
            <env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                          xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                          xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
                          xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
              <env:Header>
                <a:To>{$this->endpoint}</a:To>
                <a:MessageID>uuid:{$this->uuid()}</a:MessageID>
                <w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
                <a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
                <a:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</a:Action>
                <w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
                <w:OperationTimeout>PT10S</w:OperationTimeout>
                <w:SelectorSet>
                  <w:Selector Name="ShellId">{$shellId}</w:Selector>
                </w:SelectorSet>
              </env:Header>
              <env:Body>
                <rsp:Receive>
                  <rsp:DesiredStream CommandId="{$commandId}">stdout stderr</rsp:DesiredStream>
                </rsp:Receive>
              </env:Body>
            </env:Envelope>
            XML;

			$response = $this->soapRequest($body);
			if ($response === null) break;

			// Extract stdout/stderr streams (base64 encoded)
			preg_match_all('/<rsp:Stream Name="stdout"[^>]*>([^<]*)</', $response, $outMatches);
			preg_match_all('/<rsp:Stream Name="stderr"[^>]*>([^<]*)</', $response, $errMatches);

			foreach ($outMatches[1] ?? [] as $chunk) {
				$decoded = base64_decode($chunk, true);
				if ($decoded !== false) $stdout .= $decoded;
			}

			foreach ($errMatches[1] ?? [] as $chunk) {
				$decoded = base64_decode($chunk, true);
				if ($decoded !== false) $stderr .= $decoded;
			}

			// Check exit code
			if (preg_match('/<rsp:ExitCode>(\d+)</', $response, $m)) {
				$exitCode = (int) $m[1];
			}

			// Check if command is done
			if (str_contains($response, 'CommandState="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"')) {
				break;
			}
		}

		return [$stdout, $stderr, $exitCode];
	}

	private function deleteShell(string $shellId): void
	{
		$body = <<<XML
        <env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                      xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                      xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
          <env:Header>
            <a:To>{$this->endpoint}</a:To>
            <a:MessageID>uuid:{$this->uuid()}</a:MessageID>
            <w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd</w:ResourceURI>
            <a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</a:Action>
            <w:SelectorSet>
              <w:Selector Name="ShellId">{$shellId}</w:Selector>
            </w:SelectorSet>
          </env:Header>
          <env:Body/>
        </env:Envelope>
        XML;

		$this->soapRequest($body);
	}

	// ── Helpers ─────────────────────────────────────────────────

	private function uuid(): string
	{
		// RFC 4122 v4 UUID
		$data = random_bytes(16);
		$data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
		$data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
		return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
	}

	// ── HTTP layer ───────────────────────────────────────────────

	private function soapRequest(string $body): ?string
	{
		$ch = curl_init($this->endpoint);

		curl_setopt_array($ch, [
			CURLOPT_POST           => true,
			CURLOPT_POSTFIELDS     => $body,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER     => [
				'Content-Type: application/soap+xml;charset=UTF-8',
			],
			CURLOPT_USERPWD        => "{$this->user}:{$this->password}",
			CURLOPT_HTTPAUTH       => CURLAUTH_BASIC,
			CURLOPT_TIMEOUT        => 60,
			CURLOPT_CONNECTTIMEOUT => 10,
			CURLOPT_SSL_VERIFYPEER => false,
			CURLOPT_SSL_VERIFYHOST => 0,
		]);

		$response = curl_exec($ch);
		$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$error    = curl_error($ch);
		curl_close($ch);

		if ($response === false || $httpCode >= 400) {
			return null;
		}

		return $response;
	}

	private function errorResult(string $msg, string $cmd, int|float $startNs): ExecResult
	{
		$elapsed = (hrtime(true) - $startNs) / 1e9;
		return new ExecResult(
			exitCode: -3,
			stdout: '',
			stderr: $msg,
			durationSeconds: $elapsed,
			executor: "winrm:{$this->host}",
			command: mb_substr($cmd, 0, 200),
		);
	}
}