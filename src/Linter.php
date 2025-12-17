<?php

/*
 * Name: PHP Security Linter
 * Description: A PHP tool to lint PHP files for security issues based on CIS and OWASP best practices.
 * Version: 2.0.2.3
 * Locale: en_International
 * Last update: 2025
 * Architecture: no-arch
 * API: 7.4
 * Executor: Apache module, FPM, CGI
 * Builder:
 * License: GPL-3.0
 * Copyright: Copyright (c) 2025 Yousha Aleayoub.
 * Producer: Yousha Aleayoub
 * Maintainer: Yousha Aleayoub
 * Contact: yousha.a@hotmail.com
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

/**
 * Class Linter
 *
 * This class is responsible for scanning PHP files within a directory for security vulnerabilities.
 * It applies predefined security rules to detect unsafe patterns and reportsfindings.
 */
final class Linter
{
    /**
     * @var array Security rules to check against.
     */
    private $rules = [];

    /**
     * Constructor initializes security rules based on CIS and OWASP guidelines.
     */
    public function __construct()
    {
        $this->rules = array_merge(
            CisRules::getRules(),
            OwaspRules::getRules()
        );
    }

    /**
     * Scans PHP files ingiven directory for security issues.
     *
     * @param string $path Path todirectory to scan.
     * @param array $exclude List of file patterns or paths to exclude from scanning.
     * @return array An associative array of detected security issues by file.
     * @throws LinterException Ifspecified path does not exist.
     */
    public function scan(string $path, array $exclude = []): array
    {
        if (!file_exists($path)) {
            throw new LinterException("Path does not exist: {$path}");
        }

        $results = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path)
        );
        $phpFiles = new RegexIterator($iterator, '/^.+\.php$/i', RegexIterator::GET_MATCH);

        $scannedCount = 0;
        $issueCount = 0;

        foreach ($phpFiles as $file) {
            $filePath = $file[0];

            if ($this->shouldExclude($filePath, $exclude)) {
                continue;
            }

            $scannedCount++;
            $issues = $this->scanFile($filePath);

            if (!empty($issues)) {
                $results[$filePath] = $issues;
                $issueCount += count($issues);
            }
        }

        // Only add metadata if we actually scanned something.
        if ($scannedCount > 0) {
            $results['_meta'] = [
                'scanned_count' => $scannedCount,
                'issue_count' => $issueCount,
            ];
        }

        return $results;
    }

    /**
     * Determines whether a file should be excluded from scanning based on exclusion patterns.
     *
     * @param string $filePath The full path to the file being checked
     * @param array $exclude List of exclusion patterns/paths to match against
     * @return bool Returns true if the file matches any exclusion pattern, false otherwise
     */
    private function shouldExclude(string $filePath, array $exclude): bool
    {
        if (empty($exclude)) {
            return false;
        }

        $filePath = realpath($filePath);

        if ($filePath === false) {
            return false;
        }

        $filePath = str_replace('\\', '/', $filePath);

        foreach ($exclude as $excludedPattern) {
            $excludedPattern = trim($excludedPattern);
            if (empty($excludedPattern)) {
                continue;
            }

            if (($this->isAbsolutePathMatch($filePath, $excludedPattern)) ||
                ($this->isBasenameOrRelativePathMatch($filePath, $excludedPattern))
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if a file path matches an absolute path exclusion pattern.
     *
     * @param string $filePath The file path to check
     * @param string $excludedPattern The absolute path pattern to match against
     * @return bool Returns true if the file path starts with the excluded absolute path
     */
    private function isAbsolutePathMatch(string $filePath, string $excludedPattern): bool
    {
        if (!$this->isAbsolutePath($excludedPattern)) {
            return false;
        }

        $excludedPath = realpath($excludedPattern);

        if ($excludedPath === false) {
            return false;
        }

        $excludedPath = str_replace('\\', '/', $excludedPath);
        return strpos($filePath, $excludedPath) === 0;
    }

    /**
     * Determines if a given path is an absolute path (Unix or Windows format).
     *
     * @param string $path The path to check
     * @return bool Returns true for absolute paths (starting with / or drive letter)
     */
    private function isAbsolutePath(string $path): bool
    {
        return strpos($path, '/') === 0 ||  // Unix
            preg_match('/^[A-Za-z]:[\/\\\\]/', $path);  // Windows
    }

    /**
     * Checks if a file matches exclusion patterns based on basename or relative path.
     *
     * @param string $filePath The full file path to check
     * @param string $excludedPattern The pattern to match against (filename or partial path)
     * @return bool Returns true if basename matches exactly or pattern exists in path
     */
    private function isBasenameOrRelativePathMatch(string $filePath, string $excludedPattern): bool
    {
        return basename($filePath) === $excludedPattern ||
            strpos($filePath, $excludedPattern) !== false;
    }

    /**
     * Scans a PHP file for security vulnerabilities based on predefined rules.
     *
     * @param string $filePath Path tofile to scan.
     * @return array List of detected security issues withinfile.
     */
    private function scanFile(string $filePath): array
    {
        $issues = [];
        $content = file_get_contents($filePath);

        if ($content === false || trim($content) === '') {
            return $issues;
        }

        $lines = explode("\n", $content);

        foreach ($this->rules as $rule) {
            // Check full content first for better pattern matching.
            if (preg_match($rule['pattern'], $content)) {
                // Findline number where it occurs.
                $lineNumber = 1;
                foreach ($lines as $line) {
                    if (preg_match($rule['pattern'], $line)) {
                        $issues[] = [
                            'severity' => $rule['severity'],
                            'message' => $rule['message'],
                            'line' => $lineNumber,
                        ];
                    }

                    $lineNumber++;
                }

                // If no specific line was found, default to line 1.
                if (empty($issues) || $issues[count($issues) - 1]['message'] !== $rule['message']) {
                    $issues[] = [
                        'severity' => $rule['severity'],
                        'message' => $rule['message'],
                        'line' => 1,
                    ];
                }
            }
        }

        return $issues;
    }
}
