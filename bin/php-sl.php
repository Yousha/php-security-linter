<?php

/**
 * Console script for PHP Security Linter.
 *
 * @package PhpSecurityLinter
 */

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
 * for runningsecurity linter fromcommand line.
 *
 * @return void Outputs directly to STDOUT
 */
function showHelp(): void
{
    echo <<<HELP
        PHP Security Linter 3.0.0.3
        Usage: php bin/php-sl.php [options]

        Options:
          -p, --path=PATH      Path to scan (required)
          --exclude=LIST       Comma-separated exclusions (dirs/files)
          --help               Show this help message

        Examples:
          php bin/php-sl.php --path ./src
          php bin/php-sl.php -p ./app --exclude vendor,tests

        HELP;
}

/**
 * Outputs security scan results inspecified format.
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
    unset($results['_meta']); // Don't show meta data in file list

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
        'help',
    ];
    $options = getopt($shortOpts, $longOpts);

    if (isset($options['help'])) {
        showHelp();
        return 0;
    }


    $shortOpts = 'p:';
    $longOpts = [
        'path:',
        'exclude:',
        'help',
    ];
    $options = getopt($shortOpts, $longOpts);

    if (isset($options['help'])) {
        showHelp();
        exit(0);
    }

    // Validate path.
    $path = $options['p'] ?? $options['path'] ?? null;

    if (!$path || !is_dir($path)) {
        showHelp();
        exit(0);
    }

    // Process exclusions.
    $exclude = [];

    if (isset($options['exclude'])) {
        $exclude = is_array($options['exclude'])
            ? $options['exclude']
            : explode(',', $options['exclude']);
    }

    try {
        $linter = new Linter();
        $results = $linter->scan($path, $exclude);
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

// Only execute if run directly (not when included).
if (realpath($argv[0]) === realpath(__FILE__)) {
    runCli($argv);
}
