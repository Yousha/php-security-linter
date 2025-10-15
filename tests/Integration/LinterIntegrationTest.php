<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Integration;

use PHPUnit\Framework\TestCase;
use Yousha\PhpSecurityLinter\Linter;
use Yousha\PhpSecurityLinter\Exceptions\LinterException;

/**
 * Integration Test for the Linter class.
 *
 * This test uses actual file operations and rule sets to verify the Linter's
 * behavior without relying on mocks.
 */
final class LinterIntegrationTest extends TestCase
{
    private const string FIXTURES_DIR = __DIR__ . '/../fixtures/project_to_scan';

    /**
     * Set up a temporary directory structure for testing.
     */
    protected function setUp(): void
    {
        // 1. Create the fixture directory
        if (!is_dir(self::FIXTURES_DIR)) {
            mkdir(self::FIXTURES_DIR, 0o777, true);
        }

        // 2. Create files with known issues and non-issues

        // File 1: Contains an OWASP-002 (Command Injection) and CIS-003 (Directory Traversal)
        file_put_contents(self::FIXTURES_DIR . '/bad_code.php', <<<PHP
            <?php
            // OWASP-002: OS Command Injection risk
            \$cmd = 'ls ' . \$_GET['dir'];
            shell_exec(\$cmd);

            // CIS-003: Directory traversal vulnerability
            \$file = \$_GET['f'];
            include_once __DIR__ . '/../../views/' . \$file . '.php'; // Traversal check with /../../
            ?>
            PHP);

        // File 2: Contains a harmless file that should not trigger any rule
        file_put_contents(self::FIXTURES_DIR . '/clean_code.php', <<<PHP
            <?php
            declare(strict_types=1);
            class Clean {
                public function safeMethod(string \$data): bool {
                    return password_verify(\$data, 'hash');
                }
            }
            ?>
            PHP);

        // 3. Create a subdirectory with an ignored file
        mkdir(self::FIXTURES_DIR . '/sub_dir', 0o777, true);
        file_put_contents(self::FIXTURES_DIR . '/sub_dir/ignored_file.txt', 'This should be ignored.');

        // 4. Create a default excluded directory (e.g., vendor)
        mkdir(self::FIXTURES_DIR . '/vendor', 0o777, true);
        file_put_contents(self::FIXTURES_DIR . '/vendor/autoload.php', '<?php // vendor code');
    }

    /**
     * Clean up the temporary directory structure after tests.
     */
    protected function tearDown(): void
    {
        $this->removeDirectory(self::FIXTURES_DIR);
    }

    /**
     * Helper to recursively remove a directory.
     */
    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            (is_dir(sprintf('%s/%s', $dir, $file))) ? $this->removeDirectory(sprintf('%s/%s', $dir, $file)) : unlink(sprintf('%s/%s', $dir, $file));
        }

        rmdir($dir);
    }

    /**
     * Test that the hardcoded 'vendor' exclusion works.
     */
    public function testDefaultVendorExclusion(): void
    {
        // The Linter's scan method relies on bin/php-sl.php to inject 'vendor' and '.git'
        // into the $exclude array. Since we are testing Linter directly, we must manually
        // pass the default exclusions.

        $defaultExclusions = ['vendor', '.git'];
        $linter = new Linter();
        $results = $linter->scan(self::FIXTURES_DIR, $defaultExclusions);

        // Check the total scanned count. It should only count bad_code.php and clean_code.php
        // (The vendor directory is ignored, the sub_dir/ignored_file.txt is ignored because it's not .php)
        $this->assertArrayHasKey('_meta', $results);

        // Assert that the file inside 'vendor' was not counted
        $this->assertSame(2, $results['_meta']['scanned_count']);
    }

    /**
     * Test Linter throws LinterException for non-existent path.
     */
    public function testScanThrowsExceptionForNonExistentPath(): void
    {
        $linter = new Linter();
        $this->expectException(LinterException::class);
        $this->expectExceptionMessage('Path does not exist:');

        $linter->scan('/non/existent/path/for/linter/test');
    }
}
