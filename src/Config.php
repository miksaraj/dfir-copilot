<?php

declare(strict_types=1);

namespace DFIRCopilot;

/**
 * Configuration loader.
 * Reads a JSON config file and provides typed access to settings.
 * JSON chosen over YAML to avoid ext-yaml dependency.
 */
final class Config
{
	// REMnux
	public string $remnuxHost = '192.168.56.10';
	public string $remnuxUser = 'remnux';
	public string $remnuxKeyFile = '';
	public string $remnuxKeyPassphrase = '';
	public int    $remnuxPort = 22;
	public string $remnuxWorkDir = '/tmp/dfirbus';

	// FLARE-VM
	public string $flareHost = '192.168.56.11';
	public string $flareUser = 'flare';
	public string $flarePassword = '';
	public int    $flareWinRMPort = 5985;
	public string $flareSharedHostPath = '';
	public string $flareSharedVMPath = '';

	// Ollama
	public string $ollamaBaseUrl = 'http://localhost:11434';
	public string $ollamaWorkerModel = 'qwen3:8b';
	public string $ollamaJudgeModel = 'qwen3:8b';
	public float  $ollamaTemperature = 0.1;
	public int    $ollamaTimeout = 120;

	// Ollama advanced
	public string $ollamaKvCacheType = 'q8_0';
	public int    $ollamaContextLength = 8192;
	public bool   $ollamaWorkerThinking = true;
	public bool   $ollamaJudgeThinking = false;
	public string $ollamaHeavyModel = '';
	public string $ollamaSpecialistModel = '';

	// RAG
	public string $ragKnowledgeDir = 'knowledge';
	public string $ragEmbeddingModel = 'nomic-embed-text';
	public int    $ragChunkSize = 512;
	public int    $ragChunkOverlap = 64;
	public int    $ragTopK = 5;

	// Paths
	public string $casesRoot = 'cases';
	public string $yaraRulesDir = 'yara-rules';

	// Safety
	public int  $maxToolTimeout = 600;
	public bool $allowNetwork = false;

	public static function load(string $path = 'config.json'): self
	{
		$cfg = new self();

		if (!file_exists($path)) {
			return $cfg;
		}

		$raw = json_decode(file_get_contents($path), true);
		if (!is_array($raw)) {
			return $cfg;
		}

		$map = [
			'remnux.host'           => 'remnuxHost',
			'remnux.user'           => 'remnuxUser',
			'remnux.key_file'       => 'remnuxKeyFile',
			'remnux.key_passphrase' => 'remnuxKeyPassphrase',
			'remnux.port'           => 'remnuxPort',
			'remnux.work_dir'       => 'remnuxWorkDir',
			'flare.host'            => 'flareHost',
			'flare.user'            => 'flareUser',
			'flare.password'        => 'flarePassword',
			'flare.winrm_port'      => 'flareWinRMPort',
			'flare.shared_host_path'=> 'flareSharedHostPath',
			'flare.shared_vm_path'  => 'flareSharedVMPath',
			'ollama.base_url'       => 'ollamaBaseUrl',
			'ollama.worker_model'   => 'ollamaWorkerModel',
			'ollama.judge_model'    => 'ollamaJudgeModel',
			'ollama.temperature'    => 'ollamaTemperature',
			'ollama.timeout'        => 'ollamaTimeout',
			'ollama.kv_cache_type'  => 'ollamaKvCacheType',
			'ollama.context_length' => 'ollamaContextLength',
			'ollama.worker_thinking'    => 'ollamaWorkerThinking',
			'ollama.judge_thinking'     => 'ollamaJudgeThinking',
			'ollama.heavy_model'        => 'ollamaHeavyModel',
			'ollama.specialist_model'   => 'ollamaSpecialistModel',
			'rag.knowledge_dir'     => 'ragKnowledgeDir',
			'rag.embedding_model'   => 'ragEmbeddingModel',
			'rag.chunk_size'        => 'ragChunkSize',
			'rag.chunk_overlap'     => 'ragChunkOverlap',
			'rag.top_k'            => 'ragTopK',
			'cases_root'            => 'casesRoot',
			'yara_rules_dir'        => 'yaraRulesDir',
			'max_tool_timeout'      => 'maxToolTimeout',
			'allow_network'         => 'allowNetwork',
		];

		foreach ($map as $dotPath => $prop) {
			$parts = explode('.', $dotPath);
			$val = $raw;
			foreach ($parts as $p) {
				if (!is_array($val) || !array_key_exists($p, $val)) {
					$val = null;
					break;
				}
				$val = $val[$p];
			}
			if ($val !== null) {
				$cfg->$prop = match (gettype($cfg->$prop)) {
					'integer' => (int) $val,
					'double'  => (float) $val,
					'boolean' => (bool) $val,
					default   => (string) $val,
				};
			}
		}

		return $cfg;
	}

	public function isSingleModelMode(): bool
	{
		return $this->ollamaWorkerModel === $this->ollamaJudgeModel;
	}

	public function hasHeavyModel(): bool
	{
		return $this->ollamaHeavyModel !== '' && $this->ollamaHeavyModel !== $this->ollamaWorkerModel;
	}

	public function hasSpecialistModel(): bool
	{
		return $this->ollamaSpecialistModel !== '';
	}

	/** Resolved path to the RAG vector index file. */
	public function ragIndexPath(): string
	{
		return $this->ragKnowledgeDir . '/index.json';
	}

	public static function generateDefault(string $path = 'config.json'): void
	{
		$default = [
			'remnux' => [
				'host'           => '192.168.56.10',
				'user'           => 'remnux',
				'key_file'       => 'keys/remnux_ed25519',
				'key_passphrase' => '',
				'port'           => 22,
				'work_dir'       => '/tmp/dfirbus',
			],
			'flare' => [
				'host'             => '192.168.56.11',
				'user'             => 'flare',
				'password'         => 'flare',
				'winrm_port'       => 5985,
				'shared_host_path' => '',
				'shared_vm_path'   => '',
			],
			'ollama' => [
				'base_url'         => 'http://localhost:11434',
				'worker_model'     => 'qwen3:8b',
				'judge_model'      => 'qwen3:8b',
				'temperature'      => 0.1,
				'timeout'          => 120,
				'kv_cache_type'    => 'q8_0',
				'context_length'   => 8192,
				'worker_thinking'  => true,
				'judge_thinking'   => false,
				'heavy_model'      => '',
				'specialist_model' => '',
			],
			'rag' => [
				'knowledge_dir'   => 'knowledge',
				'embedding_model' => 'nomic-embed-text',
				'chunk_size'      => 512,
				'chunk_overlap'   => 64,
				'top_k'           => 5,
			],
			'cases_root'       => 'cases',
			'yara_rules_dir'   => 'yara-rules',
			'max_tool_timeout' => 600,
			'allow_network'    => false,
		];

		file_put_contents($path, json_encode($default, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
	}
}