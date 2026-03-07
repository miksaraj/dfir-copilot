<?php

declare(strict_types=1);

namespace DFIRCopilot\Agent;

use DFIRCopilot\Config;

/**
 * Thin wrapper around Ollama's /api/chat endpoint using native curl.
 *
 * Model selection rationale (March 2026):
 *   Default: qwen3:8b Q4_K_M (~5.2 GB, fits in 8 GB VRAM, 40–50 tok/s)
 *   - F1 0.92+ on tool calling benchmarks (Docker Model Runner eval, June 2025)
 *   - Native function-calling via chat template — no prompt-engineering hacks
 *   - Hybrid thinking/non-thinking mode for complex vs. simple tasks
 *   - Outperforms Llama 3.1:8b (F1 0.79–0.83) and Qwen2.5:14b (F1 0.81)
 *
 *   Optional heavy: qwen3:14b Q4_K_M (~9.3 GB, CPU/GPU split, 8–12 tok/s)
 *   Optional specialist: Foundation-Sec-8B (Cisco, cybersecurity-focused)
 *
 * @see https://www.docker.com/blog/local-llm-tool-calling-a-practical-evaluation/
 */
final class OllamaClient
{
	public function __construct(
		private readonly string $baseUrl,
		private readonly float  $temperature,
		private readonly int    $timeout,
		private readonly int    $contextLength = 8192,
		private readonly string $kvCacheType = 'q8_0',
	) {}

	public static function fromConfig(Config $cfg): self
	{
		return new self(
			baseUrl:       $cfg->ollamaBaseUrl,
			temperature:   $cfg->ollamaTemperature,
			timeout:       $cfg->ollamaTimeout,
			contextLength: $cfg->ollamaContextLength,
			kvCacheType:   $cfg->ollamaKvCacheType,
		);
	}

	/**
	 * Send a chat completion request.
	 *
	 * @param  string       $model       Model name (e.g. qwen3:8b)
	 * @param  list<array>  $messages    Conversation messages
	 * @param  list<array>  $tools       Ollama tool schemas (optional)
	 * @param  float|null   $temperature Override (optional)
	 * @param  bool         $thinking    Enable Qwen3 thinking mode (chain-of-thought before response)
	 * @return array                     Ollama response body
	 */
	public function chat(
		string $model,
		array  $messages,
		array  $tools = [],
		?float $temperature = null,
		bool   $thinking = true,
	): array {
		$payload = [
			'model'    => $model,
			'messages' => $messages,
			'stream'   => false,
			'options'  => [
				'temperature'  => $temperature ?? $this->temperature,
				'num_ctx'      => $this->contextLength,
			],
		];

		if (!empty($tools)) {
			$payload['tools'] = $tools;
		}

		// Qwen3 thinking mode toggle: /no_think prefix disables chain-of-thought.
		// Thinking mode adds latency but improves complex reasoning.
		// Non-thinking mode is faster for simple tool dispatches.
		if (!$thinking && !empty($messages)) {
			$lastIdx = count($messages) - 1;
			$last    = $messages[$lastIdx];
			if ($last['role'] === 'user' && is_string($last['content'])) {
				$payload['messages'][$lastIdx]['content'] = "/no_think\n" . $last['content'];
			}
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

	/**
	 * Hint for the user: environment variables that should be set before starting Ollama
	 * to optimise for 8 GB VRAM with KV cache quantisation.
	 */
	public function getRecommendedEnvVars(): array
	{
		return [
			'OLLAMA_KV_CACHE_TYPE' => $this->kvCacheType,
			'OLLAMA_NUM_PARALLEL'  => '1',               // Single-request mode saves VRAM
			'OLLAMA_MAX_LOADED_MODELS' => '1',            // Keep only one model in VRAM at a time
		];
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