<?php

declare(strict_types=1);

namespace DFIRCopilot\Rag;

use DFIRCopilot\Config;

/**
 * Knowledge base for scenario CTI, actor profiles, and analyst notes.
 *
 * This is the main entry point for the RAG layer. It orchestrates:
 *   - Ingesting documents (PDF text, markdown, plain text)
 *   - Chunking with stable IDs for citation
 *   - Embedding via Ollama (nomic-embed-text, runs on CPU)
 *   - Retrieval with cosine similarity
 *
 * Usage:
 *   $kb = KnowledgeBase::fromConfig($cfg);
 *   $kb->ingestFile('knowledge/scenario_brief.md', 'scenario_brief', ['type' => 'scenario_cti']);
 *   $kb->ingestFile('knowledge/actor_ta03.md', 'TA-03', ['type' => 'actor_profile', 'actor' => 'TA-03']);
 *   $results = $kb->search('PowerShell persistence via scheduled tasks');
 *
 * Each result includes a stable chunk ID that the LLM must cite:
 *   "TA-03:chunk_002: Known to use scheduled task persistence via schtasks..."
 */
final class KnowledgeBase
{
	private Chunker     $chunker;
	private Embedder    $embedder;
	private VectorStore $store;

	public function __construct(
		string $indexPath,
		string $ollamaBaseUrl = 'http://localhost:11434',
		string $embeddingModel = 'nomic-embed-text',
		int    $chunkSize = 512,
		int    $chunkOverlap = 64,
	) {
		$this->chunker  = new Chunker($chunkSize, $chunkOverlap);
		$this->embedder = new Embedder($ollamaBaseUrl, $embeddingModel);
		$this->store    = new VectorStore($indexPath);
	}

	public static function fromConfig(Config $cfg): self
	{
		return new self(
			indexPath:      $cfg->ragIndexPath(),
			ollamaBaseUrl:  $cfg->ollamaBaseUrl,
			embeddingModel: $cfg->ragEmbeddingModel,
			chunkSize:      $cfg->ragChunkSize,
			chunkOverlap:   $cfg->ragChunkOverlap,
		);
	}

	// ── Ingest ───────────────────────────────────────────────────

	/**
	 * Ingest a text file into the knowledge base.
	 *
	 * @param string $filePath  Path to the file
	 * @param string $docId     Stable document ID for citations (e.g., 'TA-03', 'scenario_brief')
	 * @param array  $metadata  Extra metadata (e.g., ['type' => 'actor_profile', 'actor' => 'TA-03'])
	 * @return int              Number of chunks indexed
	 */
	public function ingestFile(string $filePath, string $docId, array $metadata = []): int
	{
		if (!file_exists($filePath)) {
			throw new \RuntimeException("File not found: {$filePath}");
		}

		$text = file_get_contents($filePath);

		// Basic format detection and text extraction
		$ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
		if ($ext === 'md' || $ext === 'markdown') {
			$text = $this->stripMarkdown($text);
		}
		// For .txt and other formats, use raw text

		return $this->ingestText($text, $docId, array_merge($metadata, [
			'source_file' => basename($filePath),
			'indexed_at'  => gmdate('c'),
		]));
	}

	/**
	 * Ingest raw text into the knowledge base.
	 *
	 * @return int  Number of chunks indexed
	 */
	public function ingestText(string $text, string $docId, array $metadata = []): int
	{
		if (trim($text) === '') {
			return 0;
		}

		// Remove existing chunks for this doc (re-index)
		$this->store->removeDocument($docId);

		// Chunk the text
		$chunks = $this->chunker->chunk($text, $docId);
		if (empty($chunks)) {
			return 0;
		}

		// Embed all chunks in batches
		$batchSize = 16;
		$batches   = array_chunk($chunks, $batchSize);

		foreach ($batches as $batch) {
			$texts      = array_column($batch, 'text');
			$embeddings = $this->embedder->embedBatch($texts);

			foreach ($batch as $i => $chunk) {
				$this->store->addEntry(
					id:        $chunk['id'],
					text:      $chunk['text'],
					docId:     $chunk['doc_id'],
					offset:    $chunk['offset'],
					embedding: $embeddings[$i],
					metadata:  $metadata,
				);
			}
		}

		$this->store->save();
		return count($chunks);
	}

	/**
	 * Ingest all files from a directory.
	 *
	 * Files are given doc IDs based on their filename (without extension).
	 * Subdirectories are recursed.
	 *
	 * @return array<string, int>  Map of docId => chunk count
	 */
	public function ingestDirectory(string $dirPath, array $defaultMetadata = []): array
	{
		if (!is_dir($dirPath)) {
			throw new \RuntimeException("Directory not found: {$dirPath}");
		}

		$results = [];
		$iter    = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator($dirPath, \FilesystemIterator::SKIP_DOTS),
			\RecursiveIteratorIterator::LEAVES_ONLY
		);

		$extensions = ['txt', 'md', 'markdown', 'text', 'json'];

		foreach ($iter as $file) {
			/** @var \SplFileInfo $file */
			$ext = strtolower($file->getExtension());
			if (!in_array($ext, $extensions, true)) {
				continue;
			}

			$docId = $file->getBasename('.' . $file->getExtension());

			// Infer metadata from path
			$metadata = $defaultMetadata;
			$relPath  = ltrim(str_replace($dirPath, '', $file->getPathname()), '/');
			$metadata['source_path'] = $relPath;

			// Auto-detect type from directory name or filename
			if (str_contains($relPath, 'actor') || str_starts_with(strtolower($docId), 'ta-')) {
				$metadata['type'] = 'actor_profile';
			} elseif (str_contains($relPath, 'scenario') || str_contains($relPath, 'brief')) {
				$metadata['type'] = 'scenario_cti';
			} elseif (str_contains($relPath, 'cheat') || str_contains($relPath, 'note')) {
				$metadata['type'] = 'analyst_notes';
			}

			$chunks = $this->ingestFile($file->getPathname(), $docId, $metadata);
			$results[$docId] = $chunks;
		}

		return $results;
	}

	// ── Search ───────────────────────────────────────────────────

	/**
	 * Search the knowledge base for relevant chunks.
	 *
	 * Returns chunks with stable IDs suitable for LLM citation.
	 *
	 * @return list<array{id: string, text: string, doc_id: string, score: float, metadata: array}>
	 */
	public function search(string $query, int $topK = 5, ?string $filterDocId = null): array
	{
		$queryEmbedding = $this->embedder->embed($query);
		return $this->store->search($queryEmbedding, $topK, $filterDocId);
	}

	/**
	 * Search and format results for the LLM.
	 *
	 * Returns a text block with citations that the model can reference directly.
	 */
	public function searchFormatted(string $query, int $topK = 5): string
	{
		$results = $this->search($query, $topK);

		if (empty($results)) {
			return "No relevant knowledge base entries found for: {$query}";
		}

		$lines = ["Knowledge base results for: \"{$query}\"\n"];

		foreach ($results as $r) {
			$score = round($r['score'], 3);
			$type  = $r['metadata']['type'] ?? 'unknown';
			$lines[] = "[{$r['id']}] (score={$score}, type={$type})";
			$lines[] = $r['text'];
			$lines[] = '';
		}

		return implode("\n", $lines);
	}

	// ── Management ───────────────────────────────────────────────

	/**
	 * Remove a document from the knowledge base.
	 */
	public function removeDocument(string $docId): int
	{
		$removed = $this->store->removeDocument($docId);
		if ($removed > 0) {
			$this->store->save();
		}
		return $removed;
	}

	/**
	 * List all indexed documents.
	 */
	public function listDocuments(): array
	{
		return $this->store->listDocuments();
	}

	/**
	 * Total number of indexed chunks.
	 */
	public function chunkCount(): int
	{
		return $this->store->entryCount();
	}

	/**
	 * Clear the entire knowledge base.
	 */
	public function clear(): void
	{
		$this->store->clear();
		$this->store->save();
	}

	/**
	 * Test that the embedding model is reachable.
	 */
	public function testConnection(): array
	{
		return $this->embedder->testConnection();
	}

	// ── Text preprocessing ───────────────────────────────────────

	/**
	 * Strip markdown formatting to get cleaner text for embedding.
	 * Keeps the content, removes syntax.
	 */
	private function stripMarkdown(string $text): string
	{
		// Remove headers markers (keep text)
		$text = preg_replace('/^#{1,6}\s+/m', '', $text);
		// Remove bold/italic markers
		$text = preg_replace('/\*{1,3}([^*]+)\*{1,3}/', '$1', $text);
		$text = preg_replace('/_{1,3}([^_]+)_{1,3}/', '$1', $text);
		// Remove links, keep text: [text](url) → text
		$text = preg_replace('/\[([^\]]+)\]\([^)]+\)/', '$1', $text);
		// Remove images
		$text = preg_replace('/!\[([^\]]*)\]\([^)]+\)/', '$1', $text);
		// Remove code fences
		$text = preg_replace('/```[^`]*```/s', '', $text);
		// Remove inline code
		$text = preg_replace('/`([^`]+)`/', '$1', $text);
		// Remove horizontal rules
		$text = preg_replace('/^[-*_]{3,}\s*$/m', '', $text);
		// Remove list markers
		$text = preg_replace('/^[\s]*[-*+]\s+/m', '', $text);
		$text = preg_replace('/^[\s]*\d+\.\s+/m', '', $text);

		return $text;
	}
}