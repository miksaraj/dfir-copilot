<?php

declare(strict_types=1);

namespace DFIRCopilot\Rag;

/**
 * Computes text embeddings via Ollama's /api/embed endpoint.
 *
 * Default model: nomic-embed-text (137M params, 768-dim, fast).
 * Runs on CPU — doesn't compete with the LLM for VRAM.
 *
 * Install: ollama pull nomic-embed-text
 */
final class Embedder
{
	public function __construct(
		private readonly string $baseUrl = 'http://localhost:11434',
		private readonly string $model = 'nomic-embed-text',
		private readonly int    $timeout = 30,
	) {}

	/**
	 * Embed a single text string.
	 *
	 * @return list<float>  Embedding vector
	 */
	public function embed(string $text): array
	{
		$response = $this->request([
									   'model' => $this->model,
									   'input' => $text,
								   ]);

		// Ollama returns { "embeddings": [[...]] } for single input
		$embeddings = $response['embeddings'] ?? [];
		if (empty($embeddings) || !is_array($embeddings[0])) {
			throw new \RuntimeException('Ollama embed returned no embeddings');
		}

		return $embeddings[0];
	}

	/**
	 * Embed multiple texts in one request (batched).
	 *
	 * @param  list<string> $texts
	 * @return list<list<float>>
	 */
	public function embedBatch(array $texts): array
	{
		if (empty($texts)) {
			return [];
		}

		$response = $this->request([
									   'model' => $this->model,
									   'input' => $texts,
								   ]);

		$embeddings = $response['embeddings'] ?? [];
		if (count($embeddings) !== count($texts)) {
			throw new \RuntimeException(
				sprintf('Expected %d embeddings, got %d', count($texts), count($embeddings))
			);
		}

		return $embeddings;
	}

	/**
	 * Test that the embedding model is available.
	 */
	public function testConnection(): array
	{
		try {
			$vec = $this->embed('test');
			return [
				'connected' => true,
				'model'     => $this->model,
				'dimensions' => count($vec),
			];
		} catch (\Throwable $e) {
			return [
				'connected' => false,
				'model'     => $this->model,
				'error'     => $e->getMessage(),
			];
		}
	}

	private function request(array $payload): array
	{
		$url = rtrim($this->baseUrl, '/') . '/api/embed';
		$ch  = curl_init($url);

		curl_setopt_array($ch, [
			CURLOPT_POST           => true,
			CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_SLASHES),
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
			throw new \RuntimeException("Ollama embed request failed: {$error}");
		}

		if ($httpCode >= 400) {
			throw new \RuntimeException("Ollama embed HTTP {$httpCode}: " . mb_substr($body, 0, 300));
		}

		$decoded = json_decode($body, true);
		if (!is_array($decoded)) {
			throw new \RuntimeException("Ollama embed returned non-JSON");
		}

		return $decoded;
	}
}