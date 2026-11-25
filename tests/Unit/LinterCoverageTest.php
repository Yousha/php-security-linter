<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests\Unit;

use Yousha\PhpSecurityLinter\Linter;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * Additional coverage tests for Linter private methods and edge cases.
 * Uses real temporary files (no mocks) and follows AAA pattern.
 */
final class LinterCoverageTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->tempDir = sys_get_temp_dir() . '/php-sl-coverage-' . uniqid('', true);
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->tempDir);
        parent::tearDown();
    }

    /**
     * Test that shouldExclude and related path helpers are exercised
     * via absolute path, basename, and relative pattern exclusions.
     */
    public function testExclusionByAbsoluteBasenameAndRelativePatterns(): void
    {
        // Arrange
        $subDir = $this->tempDir . '/src/lib';
        mkdir($subDir, 0777, true);

        $vulnerableFile = $subDir . '/auth.php';
        file_put_contents($vulnerableFile, "<?php\necho \$_GET['xss'];\n");

        $excludedFile = $this->tempDir . '/src/config.php';
        file_put_contents($excludedFile, "<?php\neval(\$_POST['code']);\n");

        $linter = new Linter();

        // Act
        $results = $linter->scan($this->tempDir, [
            $excludedFile,           // absolute path
            'auth.php',              // basename
            'src/lib',               // relative path segment
        ]);

        // Assert
        $this->assertArrayHasKey('_meta', $results);
        $this->assertSame(0, $results['_meta']['scanned_count']);
        $this->assertSame(0, $results['_meta']['issue_count']);
        $this->assertEmpty(array_diff_key($results, ['_meta' => true]));
    }

    /**
     * Test scanFile handling of empty files and files that match rules
     * only on specific lines (including multi-line patterns).
     */
    public function testScanFileEmptyAndLineSpecificMatches(): void
    {
        // Arrange
        $emptyFile = $this->tempDir . '/empty.php';
        file_put_contents($emptyFile, "   \n\n");

        $matchFile = $this->tempDir . '/vuln.php';
        file_put_contents($matchFile, "<?php\n// comment\necho \$_GET['x'];\nsystem(\$_POST['cmd']);\n");

        $linter = new Linter();

        // Act
        $results = $linter->scan($this->tempDir);

        // Assert
        $this->assertSame(2, $results['_meta']['scanned_count']);
        $this->assertGreaterThan(0, $results['_meta']['issue_count']);
        $findingFiles = array_values(array_filter(
            array_keys($results),
            static function ($key): bool {
                return $key !== '_meta'
                    && basename(str_replace('\\\\', '/', (string) $key)) === 'vuln.php';
            }
        ));
        $this->assertCount(1, $findingFiles);
        $this->assertNotEmpty($results[$findingFiles[0]]);

        // Verify at least one finding has a real line number > 1
        $hasNonFirstLine = false;
        foreach ($results[$findingFiles[0]] as $issue) {
            if ($issue['line'] > 1) {
                $hasNonFirstLine = true;
                break;
            }
        }
        $this->assertTrue($hasNonFirstLine, 'Expected at least one issue reported on a line > 1');
    }

    /**
     * Test that the scanner continues and records metadata even when
     * some files cannot be processed (edge case path).
     * Note: running as root often ignores permission bits, so this
     * focuses on empty-file handling which is already covered above.
     */
    public function testScanHandlesEmptyDirectoryGracefully(): void
    {
        // Arrange
        $emptySub = $this->tempDir . '/empty-sub';
        mkdir($emptySub, 0777, true);
        $linter = new Linter();

        // Act
        $results = $linter->scan($emptySub);

        // Assert
        $this->assertSame(0, $results['_meta']['scanned_count']);
        $this->assertSame(0, $results['_meta']['issue_count']);
        $this->assertSame(0, $results['_meta']['warning_count']);
        $this->assertEmpty($results['_meta']['warnings']);
    }

    /**
     * Directly exercise private path helpers via reflection (no mocks).
     */
    public function testPrivatePathHelpersViaReflection(): void
    {
        // Arrange
        $linter = new Linter();
        $reflection = new ReflectionClass($linter);

        $isAbsolute = $reflection->getMethod('isAbsolutePath');
        $shouldExclude = $reflection->getMethod('shouldExclude');
        if (PHP_VERSION_ID < 80100) {
            $isAbsolute->setAccessible(true);
            $shouldExclude->setAccessible(true);
        }

        $filePath = $this->tempDir . '/src/app.php';
        mkdir(dirname($filePath), 0777, true);
        file_put_contents($filePath, '<?php');

        // Act & Assert – isAbsolutePath
        $this->assertTrue($isAbsolute->invoke($linter, '/absolute/path'));
        $this->assertTrue($isAbsolute->invoke($linter, 'C:\\Windows\\path'));
        $this->assertFalse($isAbsolute->invoke($linter, 'relative/path'));

        // Act & Assert – shouldExclude with various patterns
        $this->assertTrue($shouldExclude->invoke($linter, $filePath, ['app.php']));
        $this->assertTrue($shouldExclude->invoke($linter, $filePath, [dirname($filePath)]));
        $this->assertFalse($shouldExclude->invoke($linter, $filePath, ['nonexistent']));
        $this->assertFalse($shouldExclude->invoke($linter, $filePath, []));
    }

    /**
     * Direct tests for isAbsolutePathMatch and isBasenameOrRelativePathMatch.
     */
    public function testPathMatchHelpersDirectly(): void
    {
        // Arrange
        $linter = new Linter();
        $reflection = new ReflectionClass($linter);
        $absMatch = $reflection->getMethod('isAbsolutePathMatch');
        $baseMatch = $reflection->getMethod('isBasenameOrRelativePathMatch');
        if (PHP_VERSION_ID < 80100) {
            $absMatch->setAccessible(true);
            $baseMatch->setAccessible(true);
        }

        $dir = $this->tempDir . '/src';
        mkdir($dir, 0777, true);
        $file = $dir . '/app.php';
        file_put_contents($file, '<?php');
        $normalized = str_replace('\\', '/', realpath($file));

        // Act & Assert – absolute match
        $this->assertTrue($absMatch->invoke($linter, $normalized, $file));
        $this->assertFalse($absMatch->invoke($linter, $normalized, 'relative'));

        // Act & Assert – basename / relative (case-insensitive)
        $this->assertTrue($baseMatch->invoke($linter, $normalized, 'app.php'));
        $this->assertTrue($baseMatch->invoke($linter, $normalized, 'APP.PHP'));
        $this->assertTrue($baseMatch->invoke($linter, $normalized, 'src'));
        $this->assertFalse($baseMatch->invoke($linter, $normalized, 'other.php'));
    }

    /**
     * Test that Windows CRLF line endings do not prevent $ -anchored rules from matching.
     */
    public function testCrlfLineEndingsDoNotBreakAnchoredRules(): void
    {
        // Arrange
        $file = $this->tempDir . '/crlf.php';
        file_put_contents($file, "<?php\r\n\$f = \"debug.log\";\r\n");
        $linter = new Linter();

        // Act
        $results = $linter->scan($this->tempDir);

        // Assert
        $this->assertGreaterThan(0, $results['_meta']['issue_count']);
        $findingFiles = array_values(array_filter(
            array_keys($results),
            static function ($key): bool {
                return $key !== '_meta'
                    && basename(str_replace('\\\\', '/', (string) $key)) === 'crlf.php';
            }
        ));
        $this->assertCount(1, $findingFiles);

        $found = false;
        foreach ($results[$findingFiles[0]] as $issue) {
            if (str_contains($issue['message'], 'OWASP-014')) {
                $found = true;
                break;
            }
        }
        $this->assertTrue($found, 'OWASP-014 should match despite CRLF');
    }

    /**
     * Test case-insensitive exclusion so Windows mixed-case directories are excluded.
     */
    public function testCaseInsensitiveExclusion(): void
    {
        // Arrange
        $vendorDir = $this->tempDir . '/Vendor';
        mkdir($vendorDir, 0777, true);
        file_put_contents($vendorDir . '/lib.php', "<?php echo \$_GET['x'];");
        $linter = new Linter();

        // Act
        $results = $linter->scan($this->tempDir, ['vendor']);

        // Assert
        $this->assertSame(0, $results['_meta']['scanned_count']);
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $file) {
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }

        rmdir($dir);
    }
}
