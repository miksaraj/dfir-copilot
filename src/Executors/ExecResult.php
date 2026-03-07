<?php

declare(strict_types=1);

namespace DFIRCopilot\Executors;

/**
 * Standardised result from any executor.
 */
final class ExecResult
{
	public function __construct(
		public readonly int    $exitCode,
		public readonly string $stdout,
		public readonly string $stderr,
		public readonly float  $durationSeconds,
		public readonly string $executor,
		public readonly string $command,
	) {}

	public bool $ok {
		get => $this->exitCode === 0;
	}

	public function toArray(): array
	{
		return [
			'exit_code'        => $this->exitCode,
			'stdout_excerpt'   => mb_substr($this->stdout, 0, 5000),
			'stderr_excerpt'   => mb_substr($this->stderr, 0, 2000),
			'duration_seconds' => round($this->durationSeconds, 3),
			'executor'         => $this->executor,
			'command'          => $this->command,
		];
	}
}