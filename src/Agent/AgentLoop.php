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
1. NEVER fabricate evidence. Every claim must reference a specific tool output FROM THIS CYCLE.
2. Use tools systematically: identify files → triage → extract IOCs → build timeline → map TTPs → attribute.
3. When you call a tool, explain WHY (what gap it fills).
4. After each tool result, summarise what you learned and what questions remain.
5. When you have enough evidence, propose hypotheses with explicit evidence pointers.
6. For attribution, list matching AND conflicting signals for each actor candidate.

CRITICAL — ANTI-FABRICATION RULES:
- If a tool call returns an ERROR, report the error. Do NOT invent what the output "would have" shown.
- If a tool does not exist ("Unknown tool" error), report it and call a different tool. Do NOT fabricate responses for tools that fail.
- Do NOT include JSON tool-response blocks in your analysis unless they came from a real tool call this cycle.
- If knowledge_search returns an error (KB empty), do NOT invent threat intelligence results. State the KB is unavailable.
- Your analysis must be consistent with the tool calls you actually made. If you made zero tool calls, you have zero new evidence.

KNOWLEDGE BASE UNAVAILABLE — how to handle it:
- If knowledge_search returns an error ("Knowledge base is empty"), acknowledge this ONCE, then PIVOT.
- Do NOT keep requesting KB indexing — you cannot run external commands. That is an operator task.
- Instead, continue with the tools you DO have: extract_iocs, attack_map, log_parse, pcap_summary,
  strings_and_iocs, file_id, etc. Build the best analysis possible from raw evidence alone.
- Document the KB limitation as a gap in your final conclusions, not as a blocking dependency.

FILE DISCOVERY — use list_directory first:
- Before calling file_id, log_parse, extract_iocs, or strings_and_iocs on a file, call list_directory on the parent directory
  to confirm the file exists and learn its exact path.
- Call list_directory("raw/") at the start of every investigation to understand what evidence is present.
- If list_directory reports a .zip file: check whether it has been extracted. If the scenario inject mentions
  a password, use decrypt_zip to extract it before running other tools on its contents.

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
7. ZERO-TOOL FABRICATION (CRITICAL): You will be told how many tool calls were made this cycle
   ("Tool calls this cycle: N"). If N=0 but the analysis contains JSON tool-response blocks, cites
   specific tool outputs (hashes, entropy values, IOC lists, strings results), or presents structured
   adapter results — REJECT immediately. This is fabrication. The analyst invented tool outputs.
   Exception: the analyst may reference tool outputs from PREVIOUS cycles if they explicitly cite them
   as prior findings rather than presenting them as newly run results.
8. EXTERNAL DEPENDENCY LIMITATION: Do NOT emit required_actions for things the agent cannot do from
   inside the analysis loop — for example: "index the CTI KB", "run kb-index", "contact the operator",
   or any external command. The agent cannot satisfy these and the loop will stall.
   INSTEAD: if a tool is unavailable or KB is empty, APPROVE the analysis if it honestly documents
   the limitation and uses all other available tools. Add the limitation to 'issues' not
   'required_actions'.

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
			return [
				'TOOL_ERROR'      => true,
				'success'         => false,
				'error'           => "Unknown tool: {$funcName}. This tool does not exist — do NOT invent its output. Choose from the available tools instead.",
				'available_tools' => $available,
			];
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
	public function runJudge(string $workerOutput, int $toolCallsThisCycle = 0): array
	{
		$state  = $this->case->getState();
		$ledger = $this->case->getLedger();

		// Provide the last 5 ledger entries so the judge can verify claims are
		// grounded in recently run tools (not fabricated or from prior cycles).
		$recentTools = array_map(
			fn(array $e) => [
				'tool'      => $e['tool_name'],
				'exit_code' => $e['exit_code'],
				'files_out' => $e['output_paths'] ?? [],
			],
			array_slice($ledger, -5)
		);

		$judgeMessages = [
			['role' => 'system', 'content' => self::JUDGE_SYSTEM],
			[
				'role'    => 'user',
				'content' => "Review this analysis:\n\n{$workerOutput}\n\n"
					. "Tool calls this cycle: {$toolCallsThisCycle}\n"
					. "(If this is 0, any tool-output JSON blocks in the analysis are fabricated — apply Rule 7.)\n\n"
					. "Recent tools run (last 5 from provenance ledger): " . json_encode($recentTools, JSON_PRETTY_PRINT) . "\n\n"
					. "All tools run this case: " . json_encode(array_column($ledger, 'tool_name')) . "\n\n"
					. "Case state: " . mb_substr(json_encode($state, JSON_PRETTY_PRINT), 0, 1500) . "\n\n"
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
		$judgeVerdict = $this->runJudge(
			$workerResult['response'],
			$workerResult['tool_calls_made'],
		);

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
			$toolsMade = $cycleResult['tool_calls_made'] ?? 0;

			echo "Judge approved: " . ($approved ? 'YES' : 'NO') . "\n";

			// Genuinely done: approved with nothing left to do.
			if ($approved && empty($required)) {
				echo "\n✓ Analysis complete — judge approved with no outstanding actions.\n";
				break;
			}

			// Stall detection: if the same required_actions recur with zero new tool
			// calls, the agent is blocked on something it cannot resolve (e.g. empty KB,
			// missing external tool). Break after 2 consecutive stalled cycles rather
			// than burning the remaining cycle budget repeating the same conclusion.
			if ($toolsMade === 0 && !empty($required)) {
				sort($required);
				$requiredKey = implode('|', $required);
				if (isset($prevRequiredKey) && $prevRequiredKey === $requiredKey) {
					$stalledCount = ($stalledCount ?? 0) + 1;
					if ($stalledCount >= 2) {
						echo "\n⚠ Stall detected — agent cannot satisfy required actions (zero tool calls for "
							. ($stalledCount + 1) . " consecutive cycles). Stopping.\n";
						echo "  Unresolved: " . implode('; ', $required) . "\n";
						break;
					}
				} else {
					$stalledCount = 0;
				}
				$prevRequiredKey = $requiredKey;
			} else {
				$stalledCount    = 0;
				$prevRequiredKey = null;
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