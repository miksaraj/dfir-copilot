<?php

declare(strict_types=1);

namespace DFIRCopilot\Executors;

final class LocalExecutor
{
	/**
	 * @param list<string> $cmd  Command + arguments
	 */
	public function run(array $cmd, ?string $cwd = null, int $timeout = 300): ExecResult
	{
		$cmdStr = implode(' ', array_map('escapeshellarg', $cmd));
		$start  = hrtime(true);

		$descriptors = [
			0 => ['pipe', 'r'],
			1 => ['pipe', 'w'],
			2 => ['pipe', 'w'],
		];

		$proc = proc_open($cmdStr, $descriptors, $pipes, $cwd);

		if (!is_resource($proc)) {
			return new ExecResult(
				exitCode: -2,
				stdout: '',
				stderr: "Failed to start process: {$cmdStr}",
				durationSeconds: 0,
				executor: 'local',
				command: $cmdStr,
			);
		}

		fclose($pipes[0]); // close stdin

		// Non-blocking read with timeout
		stream_set_blocking($pipes[1], false);
		stream_set_blocking($pipes[2], false);

		$stdout = '';
		$stderr = '';
		$deadline = time() + $timeout;

		while (time() < $deadline) {
			$status = proc_get_status($proc);
			$stdout .= stream_get_contents($pipes[1]);
			$stderr .= stream_get_contents($pipes[2]);

			if (!$status['running']) {
				break;
			}
			usleep(50_000); // 50ms
		}

		// Final read
		$stdout .= stream_get_contents($pipes[1]);
		$stderr .= stream_get_contents($pipes[2]);

		fclose($pipes[1]);
		fclose($pipes[2]);

		$status = proc_get_status($proc);
		if ($status['running']) {
			proc_terminate($proc, 9);
			proc_close($proc);
			return new ExecResult(
				exitCode: -1,
				stdout: $stdout,
				stderr: "TIMEOUT after {$timeout}s",
				durationSeconds: (float) $timeout,
				executor: 'local',
				command: $cmdStr,
			);
		}

		$exitCode = proc_close($proc);
		// proc_close may return -1 if status was already reaped
		if ($exitCode === -1 && isset($status['exitcode'])) {
			$exitCode = $status['exitcode'];
		}

		$elapsed = (hrtime(true) - $start) / 1e9;

		return new ExecResult(
			exitCode: $exitCode,
			stdout: $stdout,
			stderr: $stderr,
			durationSeconds: $elapsed,
			executor: 'local',
			command: $cmdStr,
		);
	}
}