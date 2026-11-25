<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Yousha\PhpSecurityLinter\Exceptions\LinterException;
use Yousha\PhpSecurityLinter\Linter;

final class ScanRegressionTest extends TestCase
{
    private string $root;

    private const FINDING = "<?php\ndefine('APP_DEBUG', true);";

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/php-sl-' . bin2hex(random_bytes(8));
        mkdir($this->root);
        mkdir($this->root . '/0');
    }

    protected function tearDown(): void
    {
        $entries = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($this->root, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($entries as $entry) {
            if ($entry->isDir() && !$entry->isLink()) {
                rmdir($entry->getPathname());
            } else {
                unlink($entry->getPathname());
            }
        }
        rmdir($this->root);
    }

    private function cli(array $args, array $ini = []): array
    {
        $command = array_merge([PHP_BINARY], $ini, [dirname(__DIR__, 2) . '/bin/php-sl'], $args);
        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->root);
        self::assertIsResource($process);
        $out = stream_get_contents($pipes[1]);
        $err = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($process), $out, $err];
    }

    public function testCliHelp(): void
    {
        // Arrange
        $args = ['--help'];

        // Act
        [$code, $out, $err] = $this->cli($args);

        // Assert
        self::assertSame(0, $code);
        self::assertStringContainsString('Usage:', $out);
        self::assertStringContainsString('--path', $out);
        self::assertSame('', $err);
    }

    /** @dataProvider invalidArguments */
    public function testInvalidInputIsAnError(array $args): void
    {
        // Arrange
        file_put_contents($this->root . '/file.php', '<?php');

        // Act
        [$code, $out, $err] = $this->cli($args);

        // Assert
        self::assertSame(2, $code);
        self::assertSame('', $out);
        self::assertNotSame('', trim($err));
    }

    public static function invalidArguments(): array
    {
        return [[[]], [['--path=missing']], [['-p', 'file.php']], [['-p', '0', '--path=.']],
            [['--path=.','--format=json']], [['--path']], [['--path=']], [['extra']]];
    }

    public function testLibraryRejectsRegularFile(): void
    {
        // Arrange
        $file = $this->root . '/sample.php';
        file_put_contents($file, '<?php');
        $linter = new Linter();

        // Assert exception from the following act
        $this->expectException(LinterException::class);
        $linter->scan($file);
    }

    public function testZeroPathFindingsCleanAndBoundaryExclusions(): void
    {
        // Arrange
        mkdir($this->root . '/0/omit');
        file_put_contents($this->root . '/0/omit/a.php', self::FINDING);
        file_put_contents($this->root . '/0/omit-long.php', self::FINDING);

        // Act
        $absolute = $this->cli(['-p', '0', '--exclude=' . $this->root . '/0/omit']);
        $relative = $this->cli(['--path=0', '--exclude=omit,' . basename($this->root)]);
        $clean = $this->cli(['--path=.', '--exclude=0']);

        // Assert
        foreach ([$absolute, $relative] as [$code, $out]) {
            self::assertSame(1, $code);
            self::assertStringContainsString('omit-long.php', $out);
            self::assertStringContainsString('[OWASP A05:2021]', $out);
            self::assertStringContainsString('Scanned 1 files, found 1', $out);
        }
        self::assertSame(0, $clean[0]);
        self::assertStringContainsString('Scanned 0 files', $clean[1]);
    }

    /** @dataProvider lineEndings */
    public function testMixedMatchesHaveTheirActualStartLines(string $newline): void
    {
        // Arrange
        $file = $this->root . '/sample.php';
        file_put_contents($file, implode($newline, ['<?php', '', '', 'define(', "'APP_DEBUG', true);", "define('APP_DEBUG', true);"]));

        // Act
        $results = (new Linter())->scan($this->root);

        // Assert
        self::assertSame([4, 6], array_column($results[$file], 'line'));
    }

    public static function lineEndings(): array
    {
        return [["\n"], ["\r\n"], ["\r"]];
    }

    public function testUnreadableEntriesPreserveFindingsAndPruneExcludedDirectory(): void
    {
        // Arrange
        $file = $this->root . '/unreadable.php';
        $dir = $this->root . '/closed';
        mkdir($dir);
        file_put_contents($file, '<?php');
        file_put_contents($this->root . '/good.php', self::FINDING);
        chmod($dir, 0000);
        chmod($file, 0000);
        try {
            if (is_readable($file) || is_readable($dir)) {
                self::markTestSkipped('Requires filesystem permission enforcement.');
            }

            // Act
            $partial = $this->cli(['-p', '.']);
            $pruned = $this->cli(['-p', '.', '--exclude=closed,unreadable.php']);

            // Assert
            self::assertSame(4, $partial[0]);
            self::assertStringContainsString('Scanned 1 files, found 1', $partial[1]);
            self::assertStringContainsString('unreadable.php', $partial[2]);
            self::assertStringContainsString('closed', $partial[2]);
            self::assertSame(1, $pruned[0]);
            self::assertSame('', $pruned[2]);
        } finally {
            chmod($dir, 0700);
            chmod($file, 0600);
        }
    }

    public function testExternalLinkAndFifoAreSkipped(): void
    {
        // Arrange
        if (!function_exists('posix_mkfifo') || DIRECTORY_SEPARATOR !== '/') {
            self::markTestSkipped('Requires POSIX FIFOs and symbolic links.');
        }
        $scan = $this->root . '/0';
        file_put_contents($this->root . '/outside.php', self::FINDING);
        file_put_contents($scan . '/local.php', self::FINDING);
        symlink($this->root . '/outside.php', $scan . '/external.php');
        symlink($scan . '/local.php', $scan . '/internal.php');
        posix_mkfifo($scan . '/pipe.php', 0600);

        // Act
        $result = (new Linter())->scan($scan);

        // Assert
        self::assertSame(2, $result['_meta']['scanned_count']);
        self::assertArrayHasKey($scan . '/internal.php', $result);
        self::assertArrayNotHasKey($scan . '/external.php', $result);
    }

    public function testParseWarningTakesPrecedenceOverFindingsInTheCli(): void
    {
        // Arrange
        file_put_contents($this->root . '/good.php', self::FINDING);
        file_put_contents($this->root . '/broken.php', '<?php function (');

        // Act
        [$code, $out, $err] = $this->cli(['--path=.']);

        // Assert
        self::assertSame(4, $code);
        self::assertStringContainsString('OWASP-A5:', $out);
        self::assertStringContainsString('[OWASP A05:2021]', $out);
        self::assertStringContainsString('Scanned 2 files, found 1 potential issues.', $out);
        self::assertStringContainsString('broken.php', $err);
    }

    public function testPcreFailureMarksScanIncomplete(): void
    {
        // Arrange
        file_put_contents($this->root . '/config.php', "<?php header('Location: /home');");

        // Act
        [$code, $out, $err] = $this->cli(['-p', '.'], ['-d', 'pcre.jit=0', '-d', 'pcre.backtrack_limit=0']);

        // Assert
        self::assertSame(4, $code);
        self::assertStringContainsString('Scanned 1 files', $out);
        self::assertStringContainsString('PCRE error', $err);
        self::assertStringContainsString('config.php', $err);
    }
}
