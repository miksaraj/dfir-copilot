<?php

declare(strict_types=1);

namespace DFIRCopilot\Agent;

use DFIRCopilot\Adapters\AdapterRegistry;
use DFIRCopilot\Case\Workspace;
use DFIRCopilot\Config;

/**
 * Agentic worker → judge loop for DFIR analysis.
 *
 * Architecture (March 2026 — optimised for 8 GB VRAM):
 *
 *   By default, a SINGLE model (qwen3:8b Q4_K_M) serves both worker and judge
 *   roles with different system prompts. This eliminates the 5–15 second model-swap
 *   overhead per cycle that a dual-model setup would incur on Ollama, since only one
 *   model can occupy the GPU at a time.
 *
 *   The worker uses Qwen3's thinking mode (chain-of-thought) for complex analysis
 *   and non-thinking mode for fast tool dispatches. The judge always runs in
 *   non-thinking mode for speed — its task (validating evidence pointers) doesn't
 *   need deep reasoning.
 *
 *   Optional upgrades (configured in config.json):
 *   - heavy_model: e.g. qwen3:14b for complex reasoning (8–12 tok/s with CPU split)
 *   - specialist_model: e.g. Foundation-Sec-8B for threat intelligence tasks
 *   These are swapped in on-demand, accepting the ~10s load penalty.
 */
final class AgentLoop
{
	private OllamaClient $client;
	private array $conversationHistory = [];

	public int $maxToolCallsPerCycle = 10;
	public int $maxCycles            = 20;

	private const WORKER_SYSTEM = <<<'PROMPT'
You are a DFIR analyst copilot in a Locked Shields CDX forensics exercise.
You have access to tools (adapters) to analyse evidence.

RULES:
1. NEVER fabricate evidence. Every claim must reference a specific tool output.
2. Use tools systematically: identify files → triage → extract IOCs → build timeline → map TTPs → attribute.
3. When you call a tool, explain WHY (what gap it fills).
4. After each tool result, summarise what you learned and what questions remain.
5. When you have enough evidence, propose hypotheses with explicit evidence pointers.
6. For attribution, list matching AND conflicting signals for each actor candidate.

TOOL PATH RULES (important — wrong paths cause silent failures):
- 'file_path' and 'input_file' parameters expect paths RELATIVE to the case directory.
  Examples of CORRECT paths: "raw/LS25/DUMP_ALL/FOR_1100/main.exe", "derived/main_strings.txt"
  The case directory prefix (e.g. "cases/test-ls25/") must NOT be included.
- Absolute paths (starting with /) are passed through as-is and are also fine.

CURRENT CASE STATE:
%CASE_STATE%

AVAILABLE FILES:
%FILE_LIST%

TOOLS RUN SO FAR:
%TOOLS_RUN%

What should we do next?
PROMPT;

	private const JUDGE_SYSTEM = <<<'PROMPT'
You are a senior DFIR reviewer. Your job is to verify that analysis is honest and evidence-grounded,
not to demand a complete investigation before approving anything.

EVALUATION RULES:
1. SCOPE MATCH: Grade against what was actually attempted. A triage task does not require attribution.
   A binary analysis does not require a full timeline. Approve partial work that is honest.
2. EVIDENCE GROUNDING: Every factual claim (hash, file type, capability, IOC) must reference a tool
   output. Reject fabricated or assumed facts.
3. UNCERTAINTY: The analyst SHOULD say "likely" or "may indicate" when evidence is suggestive but not
   conclusive. Do NOT penalise appropriate hedging — only penalise fabrication.
4. COMPLETENESS vs ACCURACY: A short, accurate, evidence-backed analysis of 2 tools beats a long
   analysis with made-up details. Approve the former.
5. APPROVE when: all claims have tool backing, conclusions match the instruction scope, and gaps are
   explicitly noted. Do NOT require attribution, timeline, or full triage for a single-binary task.
6. REJECT when: claims are fabricated, paths or hashes are invented, or the analysis directly
   contradicts what the tool outputs show.

Respond ONLY with JSON:
{
  "approved": true/false,
  "issues": ["..."],
  "required_actions": ["..."],
  "confidence_assessment": "high/medium/low",
  "alternative_hypotheses": ["..."]
}
PROMPT;

	public function __construct(
		private readonly Config    $config,
		private readonly Workspace $case,
	) {
		$this->client = OllamaClient::fromConfig($config);
	}

	// ── Build context ────────────────────────────────────────────

	private function buildWorkerSystem(): string
	{
		$state  = $this->case->getState();
		$files  = $this->case->listRawFiles();
		$ledger = $this->case->getLedger();

		$toolsRun = array_map(
			fn(array $e) => [
				'tool'   => $e['tool_name'],
				'status' => $e['exit_code'] === 0 ? 'ok' : 'failed',
			],
			array_slice($ledger, -20)
		);

		return str_replace(
			['%CASE_STATE%', '%FILE_LIST%', '%TOOLS_RUN%'],
			[
				mb_substr(json_encode($state, JSON_PRETTY_PRINT), 0, 3000),
				mb_substr(json_encode($files, JSON_PRETTY_PRINT), 0, 2000),
				mb_substr(json_encode($toolsRun, JSON_PRETTY_PRINT), 0, 1000),
			],
			self::WORKER_SYSTEM,
		);
	}

	// ── Tool execution ───────────────────────────────────────────

	private function executeToolCall(array $toolCall): array
	{
		$funcName  = $toolCall['function']['name'] ?? '';
		$arguments = $toolCall['function']['arguments'] ?? [];

		$adapter = AdapterRegistry::get($funcName);
		if ($adapter === null) {
			$available = array_column(AdapterRegistry::list(), 'name');
			return ['error' => "Unknown tool: {$funcName}", 'available_tools' => $available];
		}

		try {
			$result = $adapter->run($this->case, $this->config, $arguments);
			return $result->toArray();
		} catch (\Throwable $e) {
			return ['error' => $e->getMessage(), 'tool' => $funcName];
		}
	}

	// ── Model selection ──────────────────────────────────────────

	/**
	 * Select the appropriate model for a given role.
	 *
	 * In single-model mode (default), both worker and judge use the same model
	 * (qwen3:8b) — no VRAM swap needed, zero overhead.
	 *
	 * When heavy_model is configured, it can be requested for complex reasoning
	 * tasks at the cost of a ~10s model-load penalty and reduced throughput.
	 */
	private function getWorkerModel(bool $complexTask = false): string
	{
		if ($complexTask && $this->config->hasHeavyModel()) {
			return $this->config->ollamaHeavyModel;
		}
		return $this->config->ollamaWorkerModel;
	}

	private function getJudgeModel(): string
	{
		return $this->config->ollamaJudgeModel;
	}

	// ── Worker cycle ─────────────────────────────────────────────

	public function runWorkerCycle(string $userInstruction = ''): array
	{
		$tools = AdapterRegistry::allToolSchemas();

		if (empty($this->conversationHistory)) {
			$this->conversationHistory[] = [
				'role'    => 'system',
				'content' => $this->buildWorkerSystem(),
			];
		}

		$this->conversationHistory[] = [
			'role'    => 'user',
			'content' => $userInstruction !== ''
				? $userInstruction
				: 'Based on the current case state, what should we analyse next? If you have enough evidence, propose your hypotheses and attribution.',
		];

		$toolCallsMade = 0;
		$finalResponse = null;

		while ($toolCallsMade < $this->maxToolCallsPerCycle) {
			$response = $this->client->chat(
				model:    $this->getWorkerModel(),
				messages: $this->conversationHistory,
				tools:    $tools,
				thinking: $this->config->ollamaWorkerThinking,
			);

			$message = $response['message'] ?? [];
			$this->conversationHistory[] = $message;

			$toolCalls = $message['tool_calls'] ?? [];
			if (empty($toolCalls)) {
				$finalResponse = $message['content'] ?? '';
				break;
			}

			foreach ($toolCalls as $tc) {
				$toolResult = $this->executeToolCall($tc);
				$this->conversationHistory[] = [
					'role'    => 'tool',
					'content' => mb_substr(json_encode($toolResult, JSON_PRETTY_PRINT), 0, 4000),
				];
				$toolCallsMade++;
			}
		}

			// Budget exhausted before the model stopped calling tools.
			// Ask for a final synthesis without offering any tools so the judge
			// receives real analysis text rather than the fallback placeholder.
			if ($finalResponse === null) {
				$this->conversationHistory[] = [
					'role'    => 'user',
					'content' => 'Tool budget exhausted. Summarise your findings so far: what did you confirm, what IOCs/TTPs were found, what gaps remain, and what your current hypothesis is.',
				];
				$synthResponse = $this->client->chat(
					model:    $this->getWorkerModel(),
					messages: $this->conversationHistory,
					tools:    [],   // no tools — force a prose response
					thinking: $this->config->ollamaWorkerThinking,
				);
				$finalResponse = $synthResponse['message']['content'] ?? 'No synthesis produced.';
				$this->conversationHistory[] = $synthResponse['message'] ?? [];
			}

			return [
				'response'        => $finalResponse,
				'tool_calls_made' => $toolCallsMade,
			];
	}

	// ── Judge ────────────────────────────────────────────────────

	/**
	 * Run the judge evaluation.
	 *
	 * In single-model mode, this reuses the same model already loaded in VRAM —
	 * zero swap overhead. The judge system prompt is the only difference.
	 * Non-thinking mode is used for speed since evaluation is simpler than analysis.
	 */
	public function runJudge(string $workerOutput): array
	{
		$state  = $this->case->getState();
		$ledger = $this->case->getLedger();

		$judgeMessages = [
			['role' => 'system', 'content' => self::JUDGE_SYSTEM],
			[
				'role'    => 'user',
				'content' => "Review this analysis:\n\n{$workerOutput}\n\n"
					. "Case state: " . mb_substr(json_encode($state, JSON_PRETTY_PRINT), 0, 2000) . "\n\n"
					. "Tools run: " . json_encode(array_column($ledger, 'tool_name')) . "\n\n"
					. "Provide your verdict as JSON.",
			],
		];

		$response = $this->client->chat(
			model:       $this->getJudgeModel(),
			messages:    $judgeMessages,
			temperature: 0.05,
			thinking:    $this->config->ollamaJudgeThinking,
		);

		$content = $response['message']['content'] ?? '';

		// Parse JSON (handle markdown fences)
		if (str_contains($content, '```json')) {
			$content = explode('```json', $content, 2)[1] ?? $content;
			$content = explode('```', $content, 2)[0] ?? $content;
		} elseif (str_contains($content, '```')) {
			$content = explode('```', $content, 3)[1] ?? $content;
		}

		$verdict = json_decode(trim($content), true);
		if (!is_array($verdict)) {
			$verdict = [
				'approved'     => false,
				'issues'       => ['Could not parse judge response'],
				'raw_response' => mb_substr($content, 0, 2000),
			];
		}

		return $verdict;
	}

	// ── Full cycle ───────────────────────────────────────────────

	public function runFullCycle(string $instruction = ''): array
	{
		$workerResult = $this->runWorkerCycle($instruction);
		$judgeVerdict = $this->runJudge($workerResult['response']);

		return [
			'worker_analysis'  => $workerResult['response'],
			'tool_calls_made'  => $workerResult['tool_calls_made'],
			'judge_verdict'    => $judgeVerdict,
		];
	}

	/**
	 * Auto-pilot loop: worker → judge → repeat until the judge approves with
	 * no remaining required_actions, or until max cycles is reached.
	 *
	 * WHY: The judge may approve an early cycle as "honest so far" while still
	 * listing required_actions (e.g. "run strings_and_iocs", "verify evidence.zip").
	 * Stopping on the first approval would abandon the investigation mid-flight.
	 * The loop only truly terminates when approved === true AND required_actions
	 * is empty — meaning the judge considers the work genuinely complete.
	 */
	public function runAuto(string $initialInstruction = '', ?int $maxCycles = null): array
	{
		$maxCycles   = $maxCycles ?? $this->maxCycles;
		$results     = [];
		$instruction = $initialInstruction !== '' ? $initialInstruction : 'Begin triage of all available evidence.';

		for ($cycle = 1; $cycle <= $maxCycles; $cycle++) {
			echo "\n" . str_repeat('=', 60) . "\n";
			echo "CYCLE {$cycle}\n";
			echo str_repeat('=', 60) . "\n";

			$cycleResult          = $this->runFullCycle($instruction);
			$cycleResult['cycle'] = $cycle;
			$results[]            = $cycleResult;

			echo "\nWorker: " . mb_substr($cycleResult['worker_analysis'], 0, 500) . "...\n";

			$approved = $cycleResult['judge_verdict']['approved'] ?? false;
			$required = $cycleResult['judge_verdict']['required_actions'] ?? [];
			$issues   = $cycleResult['judge_verdict']['issues'] ?? [];

			echo "Judge approved: " . ($approved ? 'YES' : 'NO') . "\n";

			// Genuinely done: approved with nothing left to do.
			if ($approved && empty($required)) {
				echo "\n✓ Analysis complete — judge approved with no outstanding actions.\n";
				break;
			}

			// Approved but still has required_actions: the judge considers the
			// current work honest but wants more. Continue with those actions.
			if ($approved && !empty($required)) {
				echo "  (approved but " . count($required) . " required action(s) remain — continuing)\n";
				$instruction = "The judge approved your analysis so far but requires these additional steps:\n"
					. implode("\n", array_map(fn($a) => "- {$a}", $required))
					. "\n\nComplete these steps before concluding.";
				continue;
			}

			// Rejected: feed back required actions or issues.
			if (!empty($required)) {
				$instruction = "The judge rejected your analysis. Required actions:\n"
					. implode("\n", array_map(fn($a) => "- {$a}", $required))
					. "\n\nAddress these issues.";
			} elseif (!empty($issues)) {
				$instruction = "The judge found issues:\n"
					. implode("\n", array_map(fn($i) => "- {$i}", $issues))
					. "\n\nPlease address these.";
			} else {
				$instruction = 'Continue the analysis.';
			}
		}

		return $results;
	}
}