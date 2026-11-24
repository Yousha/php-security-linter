<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Reporting;

use Yousha\PhpSecurityLinter\Rules\CisRules;
use Yousha\PhpSecurityLinter\Rules\OwaspRules;

/** Serializes scanner findings as SARIF 2.1.0 JSON. */
final class SarifFormatter
{
    private const SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
    private const TOOL_URI = 'https://github.com/Yousha/php-security-linter';

    /** Convert scan findings and metadata into a SARIF document. */
    public function format(array $scanResults, string $scanRoot): string
    {
        $rules = $this->getRules();
        $results = [];
        $warnings = $scanResults['_meta']['warnings'] ?? [];

        foreach ($scanResults as $file => $findings) {
            if ($file === '_meta' || !is_array($findings)) {
                continue;
            }

            foreach ($findings as $finding) {
                $message = (string) ($finding['message'] ?? '');
                $ruleId = $this->findRuleId($message, $rules);

                if ($ruleId === null || !isset($rules[$ruleId])) {
                    continue;
                }

                $rule = $rules[$ruleId];
                $result = [
                    'ruleId' => $ruleId,
                    'ruleIndex' => $rule['index'],
                    'level' => $this->mapSeverity((string) ($finding['severity'] ?? 'note')),
                    'message' => ['text' => $message !== '' ? $message : $rule['message']],
                    'locations' => [[
                        'physicalLocation' => [
                            'artifactLocation' => [
                                'uri' => $this->toArtifactUri((string) $file, $scanRoot),
                            ],
                            'region' => [
                                'startLine' => max(1, (int) ($finding['line'] ?? 1)),
                            ],
                        ],
                    ]],
                ];

                if ($rule['reference'] !== null) {
                    $result['properties'] = ['standardReference' => $rule['reference']];
                }

                $results[] = $result;
            }
        }

        $descriptors = [];
        foreach ($rules as $rule) {
            $descriptor = [
                'id' => $rule['id'],
                'shortDescription' => ['text' => $rule['shortDescription']],
                'defaultConfiguration' => ['level' => $rule['level']],
                'properties' => ['tags' => ['security']],
            ];

            if ($rule['reference'] !== null && $rule['helpUri'] !== null) {
                $descriptor['helpUri'] = $rule['helpUri'];
                $descriptor['properties']['standardReference'] = $rule['reference'];
            }

            $descriptors[] = $descriptor;
        }

        $invocation = ['executionSuccessful' => $warnings === []];
        if ($warnings !== []) {
            $invocation['toolExecutionNotifications'] = array_map(
                static fn(string $warning): array => [
                    'level' => 'warning',
                    'message' => ['text' => $warning],
                ],
                array_map('strval', $warnings)
            );
        }

        $document = [
            '$schema' => self::SCHEMA,
            'version' => '2.1.0',
            'runs' => [[
                'tool' => [
                    'driver' => [
                        'name' => 'PHP Security Linter',
                        'informationUri' => self::TOOL_URI,
                        'version' => $this->getVersion(),
                        'rules' => $descriptors,
                    ],
                ],
                'invocations' => [$invocation],
                'results' => $results,
            ]],
        ];

        return json_encode(
            $document,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
        ) . PHP_EOL;
    }

    /** Return all registered rules indexed by rule ID. */
    private function getRules(): array
    {
        $allRules = array_merge(CisRules::getRules(), OwaspRules::getRules());
        $rules = [];

        foreach ($allRules as $index => $rule) {
            $id = (string) $rule['id'];
            $message = (string) $rule['message'];
            $reference = $rule['reference'] ?? null;

            $rules[$id] = [
                'id' => $id,
                'index' => $index,
                'message' => $message,
                'shortDescription' => preg_replace(
                    '/^' . preg_quote($id, '/') . ':\s*/',
                    '',
                    $message
                ) ?? $message,
                'level' => $this->mapSeverity((string) ($rule['severity'] ?? 'note')),
                'reference' => $reference,
                'helpUri' => $this->referenceUri($reference),
            ];
        }

        return $rules;
    }

    /** Find the registered rule matching a finding message. */
    private function findRuleId(string $message, array $rules): ?string
    {
        foreach ($rules as $ruleId => $rule) {
            if ($rule['message'] === $message) {
                return $ruleId;
            }
        }

        return null;
    }

    /** Convert a scanner severity to its SARIF level. */
    private function mapSeverity(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical', 'high' => 'error',
            'medium' => 'warning',
            'low' => 'note',
            default => 'none',
        };
    }

    /** Convert a file path to a scan-root-relative artifact URI. */
    private function toArtifactUri(string $filePath, string $scanRoot): string
    {
        $root = realpath($scanRoot);
        $file = realpath($filePath);
        $normalizedRoot = rtrim(str_replace('\\', '/', $root !== false ? $root : $scanRoot), '/');
        $normalizedFile = str_replace('\\', '/', $file !== false ? $file : $filePath);

        if (str_starts_with($normalizedFile, $normalizedRoot . '/')) {
            $relative = substr($normalizedFile, strlen($normalizedRoot) + 1);
        } else {
            $relative = $normalizedFile;
        }

        return implode('/', array_map('rawurlencode', explode('/', $relative)));
    }

    /** Return the documentation URL for a known standard reference. */
    private function referenceUri(?string $reference): ?string
    {
        if ($reference === null) {
            return null;
        }

        return str_starts_with($reference, 'A')
            ? 'https://owasp.org/Top10/' . str_replace(':', '_', $reference) . '/'
            : null;
    }

    /** Read the package version from VERSION.txt. */
    private function getVersion(): string
    {
        $versionFile = dirname(__DIR__, 2) . '/VERSION.txt';
        if (is_file($versionFile)) {
            $version = trim((string) file_get_contents($versionFile));
            if ($version !== '') {
                return $version;
            }
        }

        return 'dev';
    }
}
