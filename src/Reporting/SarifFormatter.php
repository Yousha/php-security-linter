<?php

declare(strict_types=1);

namespace Yousha\\PhpSecurityLinter\\Reporting;

use Yousha\\PhpSecurityLinter\\Rules\\CisRules;
use Yousha\\PhpSecurityLinter\\Rules\\OwaspRules;

/**
 * Serializes PHP Security Linter results as SARIF 2.1.0.
 */
final class SarifFormatter
{
    private const SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
    private const VERSION = '2.1.0';
    private const TOOL_NAME = 'PHP Security Linter';
    private const TOOL_URI = 'https://github.com/Yousha/php-security-linter';

    /**
     * Format scan results as a SARIF 2.1.0 document.
     *
     * @param array<string, mixed> $scanResults Results returned by Linter::scan().
     * @param string $scanRoot Root directory used for relative artifact URIs.
     */
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
                $ruleId = $this->extractRuleId((string) ($finding['message'] ?? ''));
                $rule = $rules[$ruleId] ?? null;
                if ($ruleId === null || $rule === null) {
                    continue;
                }

                $artifactUri = $this->toArtifactUri((string) $file, $scanRoot);
                $line = max(1, (int) ($finding['line'] ?? 1));
                $result = [
                    'ruleId' => $ruleId,
                    'ruleIndex' => $rule['index'],
                    'level' => $this->mapSeverity((string) ($finding['severity'] ?? 'note')),
                    'message' => ['text' => (string) ($finding['message'] ?? $rule['message'])],
                    'locations' => [[
                        'physicalLocation' => [
                            'artifactLocation' => ['uri' => $artifactUri],
                            'region' => ['startLine' => $line],
                        ],
                    ]],
                ];

                if (isset($rule['reference'])) {
                    $result['properties'] = ['standardReference' => $rule['reference']];
                }

                $results[] = $result;
            }
        }

        $run = [
            'tool' => [
                'driver' => [
                    'name' => self::TOOL_NAME,
                    'informationUri' => self::TOOL_URI,
                    'version' => $this->getVersion(),
                    'rules' => array_values(array_map(
                        static function (array $rule): array {
                            $descriptor = [
                                'id' => $rule['id'],
                                'shortDescription' => ['text' => $rule['shortDescription']],
                                'defaultConfiguration' => ['level' => $rule['level']],
                                'properties' => ['tags' => ['security']],
                            ];
                            if (isset($rule['reference'])) {
                                $descriptor['helpUri'] = $rule['helpUri'];
                                $descriptor['properties']['standardReference'] = $rule['reference'];
                            }
                            return $descriptor;
                        },
                        $rules
                    )),
                ],
            ],
            'results' => $results,
        ];

        if ($warnings !== []) {
            $run['invocations'] = [[
                'executionSuccessful' => false,
                'toolExecutionNotifications' => array_map(
                    static fn(string $warning): array => [
                        'level' => 'warning',
                        'message' => ['text' => $warning],
                    ],
                    array_map('strval', $warnings)
                ),
            ]];
        } else {
            $run['invocations'] = [['executionSuccessful' => true]];
        }

        return json_encode([
            '$schema' => self::SCHEMA,
            'version' => self::VERSION,
            'runs' => [$run],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . PHP_EOL;
    }

    /**
     * Return registered rules keyed by stable rule identifier.
     *
     * @return array<string, array<string, mixed>>
     */
    private function getRules(): array
    {
        $allRules = array_merge(CisRules::getRules(), OwaspRules::getRules());
        $rules = [];

        foreach ($allRules as $index => $rule) {
            $id = (string) $rule['id'];
            $message = (string) $rule['message'];
            $shortDescription = preg_replace('/^' . preg_quote($id, '/') . ':\\s*/', '', $message) ?? $message;
            $reference = $rule['reference'] ?? null;
            $rules[$id] = [
                'id' => $id,
                'index' => $index,
                'message' => $message,
                'shortDescription' => $shortDescription,
                'level' => $this->mapSeverity((string) ($rule['severity'] ?? 'note')),
                'reference' => $reference,
                'helpUri' => $this->referenceUri($reference),
            ];
        }

        return $rules;
    }

    /**
     * Extract a rule identifier from the current finding message format.
     */
    private function extractRuleId(string $message): ?string
    {
        return preg_match('/^(CIS-\\d{3}|OWASP-\\d{3}):/', $message, $matches) === 1
            ? $matches[1]
            : null;
    }

    /**
     * Map linter severities to SARIF levels.
     */
    private function mapSeverity(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical', 'high' => 'error',
            'medium' => 'warning',
            'low' => 'note',
            default => 'none',
        };
    }

    /**
     * Convert a filesystem path to a normalized, scan-root-relative URI.
     */
    private function toArtifactUri(string $filePath, string $scanRoot): string
    {
        $root = realpath($scanRoot);
        $file = realpath($filePath);
        $normalizedRoot = str_replace('\\', '/', $root !== false ? $root : $scanRoot);
        $normalizedFile = str_replace('\\', '/', $file !== false ? $file : $filePath);
        $normalizedRoot = rtrim($normalizedRoot, '/');

        if ($normalizedFile === $normalizedRoot) {
            $relative = basename($normalizedFile);
        } elseif (str_starts_with($normalizedFile, $normalizedRoot . '/')) {
            $relative = substr($normalizedFile, strlen($normalizedRoot) + 1);
        } else {
            $relative = $normalizedFile;
        }

        return implode('/', array_map('rawurlencode', explode('/', $relative)));
    }

    /**
     * Return a documentation URI for a known standard reference.
     */
    private function referenceUri(?string $reference): ?string
    {
        if ($reference === null) {
            return null;
        }

        if (str_starts_with($reference, 'A')) {
            return 'https://owasp.org/Top10/' . rawurlencode($reference) . '/';
        }

        return null;
    }

    /**
     * Read the package version without requiring a generated build file.
     */
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
