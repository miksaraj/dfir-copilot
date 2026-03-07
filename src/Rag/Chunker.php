<?php

declare(strict_types=1);

namespace DFIRCopilot\Rag;

/**
 * Splits documents into overlapping text chunks with stable identifiers.
 *
 * Each chunk gets an ID like "doc_id:chunk_003" so the LLM can cite
 * specific excerpts in its analysis (e.g., "Profile TA-03:chunk_002: ...").
 *
 * No external dependencies — pure PHP string processing.
 */
final class Chunker
{
	public function __construct(
		private readonly int $chunkSize = 512,
		private readonly int $overlapSize = 64,
	) {}

	/**
	 * Split a document into chunks.
	 *
	 * @return list<array{id: string, text: string, offset: int, doc_id: string}>
	 */
	public function chunk(string $text, string $docId): array
	{
		$text = $this->normalise($text);
		if ($text === '') {
			return [];
		}

		// Split on sentence boundaries where possible
		$sentences = $this->splitSentences($text);

		$chunks   = [];
		$buffer   = '';
		$offset   = 0;
		$chunkIdx = 0;

		foreach ($sentences as $sentence) {
			// If adding this sentence would exceed chunk size, flush
			if ($buffer !== '' && mb_strlen($buffer) + mb_strlen($sentence) > $this->chunkSize) {
				$chunks[] = [
					'id'     => "{$docId}:chunk_{$chunkIdx}",
					'text'   => trim($buffer),
					'offset' => $offset,
					'doc_id' => $docId,
				];
				$chunkIdx++;

				// Keep overlap from the end of the current buffer
				if ($this->overlapSize > 0) {
					$overlapText = mb_substr($buffer, -$this->overlapSize);
					$offset += mb_strlen($buffer) - mb_strlen($overlapText);
					$buffer = $overlapText;
				} else {
					$offset += mb_strlen($buffer);
					$buffer = '';
				}
			}

			$buffer .= $sentence;
		}

		// Flush remaining
		if (trim($buffer) !== '') {
			$chunks[] = [
				'id'     => "{$docId}:chunk_{$chunkIdx}",
				'text'   => trim($buffer),
				'offset' => $offset,
				'doc_id' => $docId,
			];
		}

		return $chunks;
	}

	/**
	 * Split text into sentence-like segments.
	 * Preserves the delimiter at the end of each segment.
	 */
	private function splitSentences(string $text): array
	{
		// Split on sentence-ending punctuation followed by whitespace,
		// or on double newlines (paragraph boundaries)
		$parts = preg_split(
			'/(?<=[.!?])\s+|(?<=\n)\n+/',
			$text,
			-1,
			PREG_SPLIT_NO_EMPTY
		);

		return $parts ?: [$text];
	}

	private function normalise(string $text): string
	{
		// Collapse excessive whitespace but preserve paragraph breaks
		$text = preg_replace('/[ \t]+/', ' ', $text);
		$text = preg_replace('/\n{3,}/', "\n\n", $text);
		return trim($text);
	}
}