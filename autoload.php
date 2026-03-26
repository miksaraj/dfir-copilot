<?php

/**
 * Autoloader for the DFIRCopilot namespace.
 *
 * Several source files contain multiple classes (e.g. HostAdapters.php),
 * so we eagerly require those grouped files up front, then fall back to
 * PSR-4 (one class → one file) for everything else.
 */

// ── Eager-load grouped multi-class files ─────────────────────────
$grouped = [
	__DIR__ . '/src/Adapters/BaseAdapter.php',
	__DIR__ . '/src/Adapters/HostAdapters.php',
	__DIR__ . '/src/Adapters/REMNuxAdapters.php',
	__DIR__ . '/src/Adapters/FLAREAdapters.php',
	__DIR__ . '/src/Adapters/RagAdapter.php',
	__DIR__ . '/src/Adapters/DiskAdapters.php',
	__DIR__ . '/src/Adapters/CloudAdapters.php',
	__DIR__ . '/src/Adapters/ForensicAdapters.php',
];
foreach ($grouped as $file) {
	if (file_exists($file)) {
		require_once $file;
	}
}

// ── PSR-4 fallback for single-class-per-file additions ───────────
spl_autoload_register(function (string $class): void {
	$prefix = 'DFIRCopilot\\';
	$baseDir = __DIR__ . '/src/';

	if (!str_starts_with($class, $prefix)) {
		return;
	}

	$relativeClass = substr($class, strlen($prefix));
	$file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

	if (file_exists($file)) {
		require_once $file;
	}
});