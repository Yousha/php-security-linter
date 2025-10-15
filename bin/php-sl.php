#!/usr/bin/env php
<?php

/**
 * Console script for PHP Security Linter.
 *
 * @package PhpSecurityLinter
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "Error: This script can only be run from terminal.\n");
    exit(1);
}

$autoloadPath = __DIR__ . '/../../../../vendor/autoload.php'; // Path for Composer-installed package as user.

if (!file_exists($autoloadPath)) {
    $autoloadPath = __DIR__ . '/../vendor/autoload.php'; // Path for local development.
}

if (!file_exists($autoloadPath)) {
    fwrite(STDERR, "Error: Vendor autoload file not found. Run 'composer install'.\n");
    exit(1);
}

require_once $autoloadPath;

use Yousha\PhpSecurityLinter\Linter;
use Yousha\PhpSecurityLinter\Exceptions\LinterException;

/**
 * Displays command line help information for PHP Security Linter.
 *
 * Outputs formatted usage instructions, available options, and examples
 * for running security linter from command line.
 *
 * @return void Outputs directly to STDOUT
 */
function showHelp(): void
{
    echo <<<HELP
        PHP Security Linter
        Usage: php bin/php-sl.php [options]

        Options:
          -p, --path=PATH      Path to scan (required).
          --exclude=LIST       Comma-separated paths to exclude.
          --exclude-rules=LIST Comma-separated rule IDs to ignore.
          --help               Show this help message.

        Examples:
          php bin/php-sl.php --path ./src
          php bin/php-sl.php -p ./app --exclude .git,storage,vendor,tests
          php bin/php-sl.php -p ./src --exclude-rules CIS-003,OWASP-001

        HELP;
}

/**
 * Outputs security scan results in specified format.
 *
 * A human-readable summary is displayed with file-specific details.
 *
 * @param array $results The security scan results, indexed by file path.
 * @return void
 */
function outputResults(array $results): void
{
    $scannedCount = $results['_meta']['scanned_count'] ?? 0;
    $issueCount = $results['_meta']['issue_count'] ?? 0;
    unset($results['_meta']); // Don't show meta data in file list.
    echo "Scan results\n";
    echo str_repeat("=", 40) . "\n\n";

    foreach ($results as $file => $issues) {
        echo sprintf('File: %s%s', $file, PHP_EOL);
        foreach ($issues as $issue) {
            echo sprintf(
                "  ✗ [%s] %s (Line %d)\n",
                strtoupper((string) $issue['severity']),
                $issue['message'],
                $issue['line']
            );
        }

        echo "\n";
    }

    echo "Summary: Scanned {$scannedCount} files, found {$issueCount} potential issues.\n";
}

function runCli(array $argv): int
{
    $shortOpts = 'p:';
    $longOpts = [
        'path:',
        'exclude:',
        'exclude-rules:',
        'help',
    ];
    $options = getopt($shortOpts, $longOpts);

    if (isset($options['help'])) {
        showHelp();
        return 0;
    }

    // Validate path.
    $path = $options['p'] ?? $options['path'] ?? null;

    if (!$path || !is_dir($path)) {
        showHelp();
        exit(0);
    }

    // Process file/dir exclusions.
    $excludePaths = [
        // Default exclusions.
        'vendor',
        '.git',
        '.github',
        '.gitlab',
        '.azure-pipelines',
        '.husky',
        '.circleci',
        '.vscode',
        '.idea',
    ];

    if (isset($options['exclude'])) {
        $userExclusions = is_array($options['exclude'])
            ? $options['exclude']
            : explode(',', $options['exclude']);
        // Merge user exclusions into the default list, and ensure unique values.
        $excludePaths = array_unique(array_merge($excludePaths, $userExclusions));
    }

    // Process rule exclusions.
    $excludeRules = [];

    if (isset($options['exclude-rules'])) {
        $excludeRules = is_array($options['exclude-rules'])
            ? $options['exclude-rules']
            : explode(',', $options['exclude-rules']);
        // Normalize and trim each rule ID.
        $excludeRules = array_map('trim', $excludeRules);
    }

    try {
        // Pass rule exclusions to Linter constructor.
        $linter = new Linter($excludeRules);
        $results = $linter->scan($path, $excludePaths);
        outputResults($results);
        exit(0);
    } catch (LinterException $e) {
        fwrite(STDERR, sprintf('SCAN ERROR [%d]: %s%s', $e->getCode(), $e->getMessage(), PHP_EOL));
        exit(2);
    } catch (Exception $e) {
        fwrite(STDERR, sprintf('FATAL ERROR: %s%s', $e->getMessage(), PHP_EOL));
        exit(3);
    }
}

runCli($argv);
