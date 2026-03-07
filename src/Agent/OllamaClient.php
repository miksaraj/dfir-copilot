<?php

declare(strict_types=1);

namespace DFIRCopilot\Agent;

use DFIRCopilot\Config;

/**
 * Thin wrapper around Ollama's /api/chat endpoint using native curl.
 */
final class OllamaClient
{
	public function __construct(
		private readonly string $baseUrl,
		private readonly float  $temperature,
		private readonly int    $timeout,
	) {}

	public static function fromConfig(Config $cfg): self
	{
		return new self(
			baseUrl:     $cfg->ollamaBaseUrl,
			temperature: $cfg->ollamaTemperature,
			timeout:     $cfg->ollamaTimeout,
		);
	}

	/**
	 * Send a chat completion request.
	 *
	 * @param  string       $model    Model name (e.g. qwen2.5:14b)
	 * @param  list<array>  $messages Conversation messages
	 * @param  list<array>  $tools    Ollama tool schemas (optional)
	 * @param  float|null   $temperature Override (optional)
	 * @return array                  Ollama response body
	 */
	public function chat(
		string $model,
		array  $messages,
		array  $tools = [],
		?float $temperature = null,
	): array {
		$payload = [
			'model'    => $model,
			'messages' => $messages,
			'stream'   => false,
			'options'  => [
				'temperature' => $temperature ?? $this->temperature,
			],
		];

		if (!empty($tools)) {
			$payload['tools'] = $tools;
		}

		return $this->post('/api/chat', $payload);
	}

	/**
	 * Test connection and list available models.
	 */
	public function testConnection(): array
	{
		try {
			$resp   = $this->get('/api/tags');
			$models = array_column($resp['models'] ?? [], 'name');

			return [
				'connected' => true,
				'models'    => $models,
			];
		} catch (\Throwable $e) {
			return [
				'connected' => false,
				'error'     => $e->getMessage(),
			];
		}
	}

	// ── HTTP helpers ─────────────────────────────────────────────

	private function post(string $path, array $payload): array
	{
		$url  = rtrim($this->baseUrl, '/') . $path;
		$json = json_encode($payload, JSON_UNESCAPED_SLASHES);

		$ch = curl_init($url);
		curl_setopt_array($ch, [
			CURLOPT_POST           => true,
			CURLOPT_POSTFIELDS     => $json,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
			CURLOPT_TIMEOUT        => $this->timeout,
			CURLOPT_CONNECTTIMEOUT => 10,
		]);

		$body     = curl_exec($ch);
		$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$error    = curl_error($ch);
		curl_close($ch);

		if ($body === false) {
			throw new \RuntimeException("Ollama request failed: {$error}");
		}

		if ($httpCode >= 400) {
			throw new \RuntimeException("Ollama HTTP {$httpCode}: " . mb_substr($body, 0, 500));
		}

		$decoded = json_decode($body, true);
		if (!is_array($decoded)) {
			throw new \RuntimeException("Ollama returned non-JSON: " . mb_substr($body, 0, 200));
		}

		return $decoded;
	}

	private function get(string $path): array
	{
		$url = rtrim($this->baseUrl, '/') . $path;

		$ch = curl_init($url);
		curl_setopt_array($ch, [
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT        => 10,
			CURLOPT_CONNECTTIMEOUT => 5,
		]);

		$body  = curl_exec($ch);
		$error = curl_error($ch);
		curl_close($ch);

		if ($body === false) {
			throw new \RuntimeException("Ollama GET failed: {$error}");
		}

		return json_decode($body, true) ?: [];
	}
}