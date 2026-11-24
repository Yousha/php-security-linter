<?php

/*
 * Name: PHP Security Linter
 * Description: A PHP tool to lint PHP files for security issues based on CIS and OWASP best practices.
 * Version: 2.0.2.4
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

    /** Return findings by file and, for nonempty or incomplete scans, scan metadata. */
    public function scan(string $path, array $exclude = []): array
    {
        if (!file_exists($path)) {
            throw new LinterException("Path does not exist: {$path}");
        }
        $root = realpath($path);
        if ($root === false || !is_dir($root)) {
            throw new LinterException("Path is not a directory: {$path}");
        }

        $root = str_replace('\\', '/', $root);
        $exclude = array_map(static function (string $entry): string {
            $pattern = str_replace('\\', '/', trim($entry));
            if (strpos($pattern, '/') === 0 || preg_match('~^[a-z]:/~i', $pattern)) {
                $resolved = realpath($pattern);
                if ($resolved !== false) {
                    $pattern = str_replace('\\', '/', $resolved);
                }
                return $pattern;
            }
            return rtrim($pattern, '/');
        }, $exclude);
        $pending = $this->shouldExclude($root, '', $exclude) ? [] : [[$path, '']];
        $results = [];
        $warnings = [];
        $scanned = 0;
        $count = 0;
        while ($pending) {
            [$directory, $relativeDirectory] = array_pop($pending);
            $entries = DIRECTORY_SEPARATOR === '/' && !is_executable($directory)
                ? false
                : @scandir($directory, SCANDIR_SORT_NONE);
            if ($entries === false) {
                $warnings[] = "Could not read directory: {$directory}";
                continue;
            }
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }
                $relative = ltrim($relativeDirectory . '/' . $entry, '/');
                $absolute = rtrim($root, '/') . '/' . $relative;
                if ($this->shouldExclude($absolute, $relative, $exclude)) {
                    continue;
                }
                $file = rtrim($directory, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $entry;
                if (is_dir($file)) {
                    if (!is_link($file)) {
                        $pending[] = [$file, $relative];
                    }
                    continue;
                }
                if (strcasecmp(substr($entry, -4), '.php') !== 0 || !is_file($file)) {
                    continue;
                }
                if (is_link($file)) {
                    $target = str_replace('\\', '/', (string) realpath($file));
                    $prefix = rtrim($root, '/') . '/';
                    if (strpos($target, $prefix) !== 0 || $this->shouldExclude($target, substr($target, strlen($prefix)), $exclude)) {
                        continue;
                    }
                }
                $issues = $this->scanFile($file, $warnings);
                if ($issues === null) {
                    continue;
                }
                $scanned++;
                if ($issues) {
                    $results[$file] = $issues;
                    $count += count($issues);
                }
            }
        }
        if ($scanned || $warnings) {
            $results['_meta'] = ['scanned_count' => $scanned, 'issue_count' => $count];
            if ($warnings) {
                $results['_meta']['warnings'] = $warnings;
            }
        }
        return $results;
    }

    private function shouldExclude(string $absolute, string $relative, array $exclude): bool
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            $absolute = strtolower($absolute);
            $relative = strtolower($relative);
        }
        foreach ($exclude as $pattern) {
            if ($pattern === '') {
                continue;
            }
            if (DIRECTORY_SEPARATOR === '\\') {
                $pattern = strtolower($pattern);
            }
            if ($pattern[0] === '/' || preg_match('~^[a-z]:/~i', $pattern)) {
                if ($absolute === $pattern || strpos($absolute, rtrim($pattern, '/') . '/') === 0) {
                    return true;
                }
                continue;
            }
            if (strpos($pattern, './') === 0) {
                $pattern = substr($pattern, 2);
            }
            if ($relative === $pattern || strpos('/' . $relative . '/', '/' . $pattern . '/') !== false) {
                return true;
            }
        }
        return false;
    }

    private function scanFile(string $file, array &$warnings): ?array
    {
        $content = @file_get_contents($file);
        if ($content === false) {
            $warnings[] = "Could not read file: {$file}";
            return null;
        }
        $content = str_replace(["\r\n", "\r"], "\n", $content);
        $issues = [];
        foreach ($this->rules as $rule) {
            $cursor = 0;
            $previousOffset = 0;
            $line = 1;
            $reportedLine = 0;
            while (($matched = preg_match($rule['pattern'], $content, $match, PREG_OFFSET_CAPTURE, $cursor)) === 1) {
                [$text, $offset] = $match[0];
                if ($offset > $previousOffset) {
                    $line += substr_count($content, "\n", $previousOffset, $offset - $previousOffset);
                }
                $previousOffset = $offset;
                if ($line !== $reportedLine) {
                    $issues[] = ['severity' => $rule['severity'], 'message' => $rule['message'], 'line' => $line];
                    $reportedLine = $line;
                }
                $cursor = $offset + max(1, strlen($text));
                if ($cursor > strlen($content)) {
                    break;
                }
            }
            if ($matched === false) {
                $warnings[] = sprintf('PCRE error %d in %s for %s', preg_last_error(), $file, $rule['message']);
            }
        }
        return $issues;
    }
}
