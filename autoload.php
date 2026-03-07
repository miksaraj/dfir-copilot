<?php

/**
 * Simple PSR-4 autoloader for the DFIRCopilot namespace.
 * No Composer required.
 */
spl_autoload_register(function (string $class): void {
	$prefix  = 'DFIRCopilot\\';
	$baseDir = __DIR__ . '/src/';

	if (!str_starts_with($class, $prefix)) {
		return;
	}

	$relativeClass = substr($class, strlen($prefix));
	$file          = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';

	if (file_exists($file)) {
		require_once $file;
	}
});