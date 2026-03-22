<?php

declare(strict_types=1);

namespace DFIRCopilot\Adapters;

final class AdapterRegistry
{
    /** @var array<string, BaseAdapter> */
    private static array $adapters = [];

    public static function register(BaseAdapter $adapter): void
    {
        self::$adapters[$adapter::NAME] = $adapter;
    }

    public static function get(string $name): ?BaseAdapter
    {
        return self::$adapters[$name] ?? null;
    }

    /** @return list<array{name: string, description: string, target: string, schema: array}> */
    public static function list(): array
    {
        $list = [];
        foreach (self::$adapters as $a) {
            $list[] = [
                'name' => $a::NAME,
                'description' => $a::DESCRIPTION,
                'target' => $a::TARGET,
                'schema' => $a->getToolSchema(),
            ];
        }
        return $list;
    }

    /** Get all tool schemas formatted for Ollama tool-calling. */
    public static function allToolSchemas(): array
    {
        $schemas = [];
        foreach (self::$adapters as $a) {
            $schemas[] = [
                'type' => 'function',
                'function' => $a->getToolSchema(),
            ];
        }
        return $schemas;
    }

    public static function reset(): void
    {
        self::$adapters = [];
    }
}