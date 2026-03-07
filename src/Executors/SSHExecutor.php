<?php

declare(strict_types=1);

namespace DFIRCopilot\Executors;

use DFIRCopilot\Config;

/**
 * Runs commands on REMnux (or any Linux VM) via the php-ssh2 extension.
 *
 * Install: sudo apt install php-ssh2   (or pecl install ssh2)
 */
final class SSHExecutor
{
	/** @var resource|null */
	private mixed $connection = null;

	/** @var resource|null */
	private mixed $sftp = null;

	public function __construct(
		private readonly string $host,
		private readonly string $user,
		private readonly string $keyFile = '',
		private readonly string $keyPassphrase = '',
		private readonly int    $port = 22,
	) {}

	public static function fromConfig(Config $cfg): self
	{
		return new self(
			host:          $cfg->remnuxHost,
			user:          $cfg->remnuxUser,
			keyFile:       $cfg->remnuxKeyFile,
			keyPassphrase: $cfg->remnuxKeyPassphrase,
			port:          $cfg->remnuxPort,
		);
	}

	// ── Connection management ────────────────────────────────────

	/**
	 * @return resource  SSH2 connection
	 */
	private function connect(): mixed
	{
		if ($this->connection !== null) {
			return $this->connection;
		}

		if (!function_exists('ssh2_connect')) {
			throw new \RuntimeException(
				'php-ssh2 extension not loaded. Install: sudo apt install php-ssh2'
			);
		}

		$conn = ssh2_connect($this->host, $this->port);
		if ($conn === false) {
			throw new \RuntimeException(
				"SSH: cannot connect to {$this->host}:{$this->port}"
			);
		}

		if ($this->keyFile !== '' && file_exists($this->keyFile)) {
			$pubKey = $this->keyFile . '.pub';
			if (!file_exists($pubKey)) {
				// Try without explicit pub key (some setups)
				$pubKey = $this->keyFile;
			}
			$ok = ssh2_auth_pubkey_file(
				$conn,
				$this->user,
				$pubKey,
				$this->keyFile,
				$this->keyPassphrase,
			);
		} else {
			// Fall back to agent auth
			$ok = ssh2_auth_agent($conn, $this->user);
		}

		if (!$ok) {
			throw new \RuntimeException(
				"SSH: authentication failed for {$this->user}@{$this->host}"
			);
		}

		$this->connection = $conn;
		return $conn;
	}

	private function getSftp(): mixed
	{
		if ($this->sftp !== null) {
			return $this->sftp;
		}

		$conn = $this->connect();
		$sftp = ssh2_sftp($conn);
		if ($sftp === false) {
			throw new \RuntimeException('SSH: failed to initialise SFTP subsystem');
		}

		$this->sftp = $sftp;
		return $sftp;
	}

	public function disconnect(): void
	{
		// php-ssh2 doesn't have an explicit disconnect;
		// the connection closes when the resource is unset / GC'd.
		$this->sftp       = null;
		$this->connection = null;
	}

	// ── Command execution ────────────────────────────────────────

	public function run(string $remoteCmd, int $timeout = 300): ExecResult
	{
		$start = hrtime(true);

		try {
			$conn   = $this->connect();
			$stream = ssh2_exec($conn, $remoteCmd);

			if ($stream === false) {
				return new ExecResult(-1, '', 'ssh2_exec failed', 0, "ssh:{$this->host}", $remoteCmd);
			}

			$stderrStream = ssh2_fetch_stream($stream, SSH2_STREAM_STDERR);

			stream_set_blocking($stream, true);
			stream_set_blocking($stderrStream, true);

			// Set a socket timeout so we don't block forever
			stream_set_timeout($stream, $timeout);
			stream_set_timeout($stderrStream, $timeout);

			$stdout = stream_get_contents($stream);
			$stderr = stream_get_contents($stderrStream);

			// Get exit status
			$meta     = stream_get_meta_data($stream);
			$exitCode = 0;
			// ssh2 stores exit status after stream close in some implementations
			fclose($stderrStream);
			fclose($stream);

			// Try to get exit status via a follow-up echo
			$checkStream = ssh2_exec($conn, 'echo $?');
			if ($checkStream !== false) {
				stream_set_blocking($checkStream, true);
				stream_set_timeout($checkStream, 5);
				$exitStr = trim(stream_get_contents($checkStream));
				fclose($checkStream);
				if (is_numeric($exitStr)) {
					$exitCode = (int) $exitStr;
				}
			}

			$elapsed = (hrtime(true) - $start) / 1e9;

			return new ExecResult(
				exitCode: $exitCode,
				stdout: $stdout,
				stderr: $stderr,
				durationSeconds: $elapsed,
				executor: "ssh:{$this->host}",
				command: $remoteCmd,
			);
		} catch (\Throwable $e) {
			$elapsed = (hrtime(true) - $start) / 1e9;
			return new ExecResult(
				exitCode: -3,
				stdout: '',
				stderr: "SSH error: {$e->getMessage()}",
				durationSeconds: $elapsed,
				executor: "ssh:{$this->host}",
				command: $remoteCmd,
			);
		}
	}

	// ── File transfer via SFTP ───────────────────────────────────

	public function copyTo(string $localPath, string $remotePath): bool
	{
		$sftp    = $this->getSftp();
		$sftpInt = (int) $sftp;  // intval for the stream wrapper

		// Ensure remote directory exists
		$remoteDir = dirname($remotePath);
		@ssh2_sftp_mkdir($sftp, $remoteDir, 0755, true);

		$remote = fopen("ssh2.sftp://{$sftpInt}{$remotePath}", 'w');
		if ($remote === false) {
			return false;
		}

		$local = fopen($localPath, 'r');
		if ($local === false) {
			fclose($remote);
			return false;
		}

		while (!feof($local)) {
			$chunk = fread($local, 8192);
			if ($chunk === false) break;
			fwrite($remote, $chunk);
		}

		fclose($local);
		fclose($remote);
		return true;
	}

	public function copyFrom(string $remotePath, string $localPath): bool
	{
		$sftp    = $this->getSftp();
		$sftpInt = (int) $sftp;

		$remote = @fopen("ssh2.sftp://{$sftpInt}{$remotePath}", 'r');
		if ($remote === false) {
			return false;
		}

		$localDir = dirname($localPath);
		if (!is_dir($localDir)) {
			mkdir($localDir, 0755, true);
		}

		$local = fopen($localPath, 'w');
		if ($local === false) {
			fclose($remote);
			return false;
		}

		while (!feof($remote)) {
			$chunk = fread($remote, 8192);
			if ($chunk === false) break;
			fwrite($local, $chunk);
		}

		fclose($remote);
		fclose($local);
		return true;
	}

	// ── Connectivity test ────────────────────────────────────────

	public function testConnection(): bool
	{
		try {
			$r = $this->run('echo ok', 15);
			return $r->ok && str_contains($r->stdout, 'ok');
		} catch (\Throwable) {
			return false;
		}
	}
}