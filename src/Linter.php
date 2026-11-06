<?php

/*
 * Name: PHP Security Linter
 * Description: A PHP tool to lint PHP files for security issues based on CIS and OWASP best practices.
 * Version: 3.1.8.6
 * Locale: en_International
 * Last update: 2026
 * Architecture: no-arch
 * API: 8.2
 * Executor: Apache module, FPM, CGI
 * Builder:
 * License: GPL-3.0
 * Copyright: Copyright (c) 2026 Yousha Aleayoub.
 * Producer: Yousha Aleayoub
 * Maintainer: Yousha Aleayoub
 * Contact: y.aleayoub@gmail.com
 * Link: http://yousha.blog.ir
 */

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter;

use Yousha\PhpSecurityLinter\Rules\CisRules;
use Yousha\PhpSecurityLinter\Rules\OwaspRules;
use Yousha\PhpSecurityLinter\Exceptions\LinterException;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RegexIterator;
use FilesystemIterator;
use UnexpectedValueException;

/**
 * Scans PHP files in a directory and reports security-rule matches.
 */
final readonly class Linter
{
    /** @var array Security rules to check against. */
    private array $rules;

    /**
     * @param array $excludeRuleIds List of rule IDs to exclude.
     */
    public function __construct(
        private array $excludedRuleIds = []
    ) {
        $allRules = array_merge(CisRules::getRules(), OwaspRules::getRules());
        $this->rules = array_filter(
            $allRules,
            fn(array $rule): bool => !in_array($rule['id'], $this->excludedRuleIds, true)
        );
    }

    /**
     * Scan all PHP files below a directory.
     *
     * Unreadable files and directories are recorded as warnings. The scan
     * continues where possible; callers can inspect _meta.warnings.
     *
     * @param string $path Directory path to scan.
     * @param array $exclude Paths to exclude.
     * @return array Findings keyed by file, plus scan metadata.
     * @throws LinterException If the path does not exist or is not a directory.
     */
    public function scan(string $path, array $exclude = []): array
    {
        if (!file_exists($path)) {
            throw new LinterException('Path does not exist: ' . $path);
        }

        if (!is_dir($path)) {
            throw new LinterException('Path is not a directory: ' . $path);
        }

        $results = [];
        $warnings = [];
        $scannedCount = 0;
        $issueCount = 0;

        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS)
            );
            $phpFiles = new RegexIterator($iterator, '/^.+\.php$/i', RegexIterator::GET_MATCH);

            foreach ($phpFiles as $file) {
                $filePath = $file[0];
                if ($this->shouldExclude($filePath, $exclude)) {
                    continue;
                }

                $issues = $this->scanFile($filePath, $warnings);
                if ($issues === null) {
                    continue;
                }

                $scannedCount++;
                if ($issues !== []) {
                    $results[$filePath] = $issues;
                    $issueCount += count($issues);
                }
            }
        } catch (UnexpectedValueException $unexpectedValueException) {
            $warnings[] = sprintf('Could not traverse directory: %s', $unexpectedValueException->getMessage());
        }

        $results['_meta'] = [
            'scanned_count' => $scannedCount,
            'issue_count' => $issueCount,
            'warning_count' => count($warnings),
            'warnings' => $warnings,
        ];

        return $results;
    }

    /**
     * Determine whether a file should be excluded.
     */
    private function shouldExclude(string $filePath, array $exclude): bool
    {
        if ($exclude === []) {
            return false;
        }

        $resolvedFilePath = realpath($filePath);
        if ($resolvedFilePath === false) {
            return false;
        }

        $normalizedFilePath = str_replace('\\', '/', $resolvedFilePath);

        foreach ($exclude as $excludedPattern) {
            $excludedPattern = trim((string) $excludedPattern);
            if ($excludedPattern === '') {
                continue;
            }

            if ($this->isAbsolutePathMatch($normalizedFilePath, $excludedPattern)
                || $this->isBasenameOrRelativePathMatch($normalizedFilePath, $excludedPattern)) {
                return true;
            }
        }

        return false;
    }

    private function isAbsolutePathMatch(string $filePath, string $excludedPattern): bool
    {
        if (!$this->isAbsolutePath($excludedPattern)) {
            return false;
        }

        $excludedPath = realpath($excludedPattern);
        if ($excludedPath === false) {
            return false;
        }

        $excludedPath = rtrim(str_replace('\\', '/', $excludedPath), '/');
        return $filePath === $excludedPath || str_starts_with($filePath, $excludedPath . '/');
    }

    private function isAbsolutePath(string $path): bool
    {
        return str_starts_with($path, '/')
            || preg_match('/^[A-Za-z]:[\/\\\\]/', $path) === 1;
    }

    private function isBasenameOrRelativePathMatch(string $filePath, string $excludedPattern): bool
    {
        $normalizedPattern = str_replace('\\', '/', $excludedPattern);
        if (basename($filePath) === $normalizedPattern) {
            return true;
        }

        return str_contains('/' . ltrim($filePath, '/') . '/', '/' . trim($normalizedPattern, '/') . '/');
    }

    /**
     * @param string[] $warnings Warnings collected during the scan.
     * @return array|null Null means the file could not be read.
     */
    private function scanFile(string $filePath, array &$warnings): ?array
    {
        $content = @file_get_contents($filePath);
        if ($content === false) {
            $warnings[] = sprintf('Could not read file: %s', $filePath);
            return null;
        }

        if (trim($content) === '') {
            return [];
        }

        $issues = [];
        $lines = explode("\n", $content);

        foreach ($this->rules as $rule) {
            if (preg_match($rule['pattern'], $content) !== 1) {
                continue;
            }

            $foundOnLine = false;
            foreach ($lines as $index => $line) {
                if (preg_match($rule['pattern'], $line) === 1) {
                    $issues[] = [
                        'severity' => $rule['severity'],
                        'message' => $rule['message'],
                        'line' => $index + 1,
                    ];
                    $foundOnLine = true;
                }
            }

            if (!$foundOnLine) {
                $issues[] = [
                    'severity' => $rule['severity'],
                    'message' => $rule['message'],
                    'line' => 1,
                ];
            }
        }

        return $issues;
    }
}
