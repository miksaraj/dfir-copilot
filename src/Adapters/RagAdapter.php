<?php

declare(strict_types=1);

namespace DFIRCopilot\Adapters;

use DFIRCopilot\Case\Workspace;
use DFIRCopilot\Config;
use DFIRCopilot\Executors\ExecResult;
use DFIRCopilot\Rag\KnowledgeBase;

/**
 * Adapter that lets the agent search the scenario CTI knowledge base.
 *
 * This is the bridge between the agent loop and the RAG layer.
 * The agent calls this like any other tool:
 *
 *   knowledge_search(query="scheduled task persistence APT group")
 *
 * Results come back with stable chunk IDs the model must cite:
 *   [TA-03:chunk_002] (score=0.87, type=actor_profile)
 *   Known to use schtasks for persistence...
 */
final class KnowledgeSearch extends BaseAdapter
{
	public const NAME        = 'knowledge_search';
	public const VERSION     = '1.0.0';
	public const DESCRIPTION = 'Search the scenario CTI knowledge base for threat actor profiles, TTPs, IOCs, and analyst notes. Returns citable excerpts.';
	public const TARGET      = 'local';

	public function getToolSchema(): array
	{
		return [
			'name'        => self::NAME,
			'description' => self::DESCRIPTION,
			'parameters'  => [
				'type'       => 'object',
				'properties' => [
					'query' => [
						'type'        => 'string',
						'description' => 'Search query — describe what you are looking for (e.g., "actor using DNS tunneling for exfiltration", "PowerShell persistence techniques")',
					],
					'top_k' => [
						'type'        => 'integer',
						'description' => 'Number of results to return (default: 5)',
						'default'     => 5,
					],
					'filter_doc' => [
						'type'        => 'string',
						'description' => 'Optional: restrict search to a specific document ID (e.g., "TA-03")',
						'default'     => '',
					],
				],
				'required' => ['query'],
			],
		];
	}

	protected function execute(Workspace $case, Config $config, array $params): AdapterResult
	{
		$query     = $this->requireParam($params, 'query');
		$topK      = (int) ($params['top_k'] ?? $config->ragTopK);
		$filterDoc = ($params['filter_doc'] ?? '') !== '' ? $params['filter_doc'] : null;

		try {
			$kb = KnowledgeBase::fromConfig($config);
		} catch (\Throwable $e) {
			return $this->errorResult("Failed to initialise knowledge base: {$e->getMessage()}");
		}

		if ($kb->chunkCount() === 0) {
			return new AdapterResult(
				adapterName:       self::NAME,
				success:           true,
				producedFiles:     [],
				structuredResults: ['results' => [], 'note' => 'Knowledge base is empty. Run: php dfirbus.php kb-index'],
				evidencePointers:  [],
				stdoutExcerpt:     'Knowledge base is empty — index documents first.',
				stderrExcerpt:     '',
				execResult:        new ExecResult(0, '', '', 0, 'local', "knowledge_search \"{$query}\""),
			);
		}

		try {
			$results = $kb->search($query, $topK, $filterDoc);
		} catch (\Throwable $e) {
			return $this->errorResult("Knowledge base search failed: {$e->getMessage()}");
		}

		// Format for the LLM with stable citation IDs
		$formatted = [];
		$evidence  = [];
		foreach ($results as $r) {
			$formatted[] = [
				'chunk_id'  => $r['id'],
				'text'      => $r['text'],
				'score'     => round($r['score'], 3),
				'doc_id'    => $r['doc_id'],
				'type'      => $r['metadata']['type'] ?? 'unknown',
			];
			$evidence[] = "kb:{$r['id']}:score=" . round($r['score'], 3);
		}

		return new AdapterResult(
			adapterName:       self::NAME,
			success:           true,
			producedFiles:     [],
			structuredResults: ['query' => $query, 'result_count' => count($formatted), 'results' => $formatted],
			evidencePointers:  $evidence,
			stdoutExcerpt:     "KB search \"{$query}\": " . count($formatted) . " results",
			stderrExcerpt:     '',
			execResult:        new ExecResult(0, '', '', 0, 'local', "knowledge_search \"{$query}\""),
		);
	}
}