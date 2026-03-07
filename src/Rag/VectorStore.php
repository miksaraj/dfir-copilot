<?php

declare(strict_types=1);

namespace DFIRCopilot\Rag;

/**
 * Flat-file vector store for RAG retrieval.
 *
 * Stores chunks + embeddings as a single JSON file per knowledge base.
 * Uses brute-force cosine similarity — perfectly adequate for the
 * typical Locked Shields knowledge base size (50–200 chunks).
 *
 * No external database, no extensions, no dependencies.
 * The entire index lives in one file: knowledge/index.json
 */
final class VectorStore
{
	/** @var list<array{id: string, text: string, doc_id: string, offset: int, embedding: list<float>, metadata: array}> */
	private array $entries = [];

	private bool $dirty = false;

	public function __construct(
		private readonly string $indexPath,
	) {
		$this->load();
	}

	// ── Index management ─────────────────────────────────────────

	public function load(): void
	{
		if (file_exists($this->indexPath)) {
			$data = json_decode(file_get_contents($this->indexPath), true);
			$this->entries = $data['entries'] ?? [];
		}
	}

	public function save(): void
	{
		if (!$this->dirty) {
			return;
		}

		$dir = dirname($this->indexPath);
		if (!is_dir($dir)) {
			mkdir($dir, 0755, true);
		}

		$data = [
			'version'    => 1,
			'entry_count' => count($this->entries),
			'updated_at' => gmdate('c'),
			'entries'    => $this->entries,
		];

		file_put_contents(
			$this->indexPath,
			json_encode($data, JSON_UNESCAPED_SLASHES) . "\n",
			LOCK_EX
		);

		$this->dirty = false;
	}

	/**
	 * Add a chunk with its embedding to the store.
	 */
	public function addEntry(
		string $id,
		string $text,
		string $docId,
		int    $offset,
		array  $embedding,
		array  $metadata = [],
	): void {
		// Update existing entry if same ID
		foreach ($this->entries as $i => $entry) {
			if ($entry['id'] === $id) {
				$this->entries[$i] = [
					'id'        => $id,
					'text'      => $text,
					'doc_id'    => $docId,
					'offset'    => $offset,
					'embedding' => $embedding,
					'metadata'  => $metadata,
				];
				$this->dirty = true;
				return;
			}
		}

		$this->entries[] = [
			'id'        => $id,
			'text'      => $text,
			'doc_id'    => $docId,
			'offset'    => $offset,
			'embedding' => $embedding,
			'metadata'  => $metadata,
		];
		$this->dirty = true;
	}

	/**
	 * Remove all entries for a given document.
	 */
	public function removeDocument(string $docId): int
	{
		$before = count($this->entries);
		$this->entries = array_values(
			array_filter($this->entries, fn($e) => $e['doc_id'] !== $docId)
		);
		$removed = $before - count($this->entries);
		if ($removed > 0) {
			$this->dirty = true;
		}
		return $removed;
	}

	/**
	 * Retrieve the top-k most similar chunks to a query embedding.
	 *
	 * @param  list<float> $queryEmbedding
	 * @return list<array{id: string, text: string, doc_id: string, score: float, metadata: array}>
	 */
	public function search(array $queryEmbedding, int $topK = 5, ?string $filterDocId = null): array
	{
		$scored = [];

		foreach ($this->entries as $entry) {
			if ($filterDocId !== null && $entry['doc_id'] !== $filterDocId) {
				continue;
			}

			$score = $this->cosineSimilarity($queryEmbedding, $entry['embedding']);

			$scored[] = [
				'id'       => $entry['id'],
				'text'     => $entry['text'],
				'doc_id'   => $entry['doc_id'],
				'score'    => $score,
				'metadata' => $entry['metadata'] ?? [],
			];
		}

		// Sort by score descending
		usort($scored, fn($a, $b) => $b['score'] <=> $a['score']);

		return array_slice($scored, 0, $topK);
	}

	/**
	 * List all indexed documents with chunk counts.
	 *
	 * @return list<array{doc_id: string, chunks: int, metadata: array}>
	 */
	public function listDocuments(): array
	{
		$docs = [];
		foreach ($this->entries as $entry) {
			$docId = $entry['doc_id'];
			if (!isset($docs[$docId])) {
				$docs[$docId] = [
					'doc_id'   => $docId,
					'chunks'   => 0,
					'metadata' => $entry['metadata'] ?? [],
				];
			}
			$docs[$docId]['chunks']++;
		}
		return array_values($docs);
	}

	public function entryCount(): int
	{
		return count($this->entries);
	}

	/**
	 * Clear all entries.
	 */
	public function clear(): void
	{
		$this->entries = [];
		$this->dirty = true;
	}

	// ── Math ─────────────────────────────────────────────────────

	/**
	 * Cosine similarity between two vectors.
	 *
	 * @param list<float> $a
	 * @param list<float> $b
	 */
	private function cosineSimilarity(array $a, array $b): float
	{
		$dim = min(count($a), count($b));
		if ($dim === 0) {
			return 0.0;
		}

		$dot  = 0.0;
		$normA = 0.0;
		$normB = 0.0;

		for ($i = 0; $i < $dim; $i++) {
			$dot   += $a[$i] * $b[$i];
			$normA += $a[$i] * $a[$i];
			$normB += $b[$i] * $b[$i];
		}

		$denom = sqrt($normA) * sqrt($normB);
		if ($denom < 1e-10) {
			return 0.0;
		}

		return $dot / $denom;
	}
}