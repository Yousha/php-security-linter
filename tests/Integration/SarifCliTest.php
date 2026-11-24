<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests\Integration;

use PHPUnit\Framework\TestCase;

/**
 * Exercises the SARIF CLI using real PHP processes and filesystem fixtures.
 */
#[\PHPUnit\Framework\Attributes\Small]
final class SarifCliTest extends TestCase
{
    /**
     * Verify SARIF can be emitted to standard output.
     */
    public function testWritesSarifToStandardOutput(): void
    {
        // Arrange
        $directory = $this->createFixtureDirectory();

        try {
            // Act
            $process = $this->runCli([
                '--path=' . $directory,
                '--format=sarif',
            ]);
            $document = json_decode($process['stdout'], true, 512, JSON_THROW_ON_ERROR);

            // Assert
            self::assertSame(0, $process['exitCode']);
            self::assertSame('2.1.0', $document['version']);
            self::assertSame(
                'OWASP-002',
                $document['runs'][0]['results'][0]['ruleId']
            );
            self::assertSame('', $process['stderr']);
        } finally {
            $this->removeFixtureDirectory($directory);
        }
    }

    /**
     * Verify SARIF can be written to a file without polluting standard output.
     */
    public function testWritesSarifToOutputFile(): void
    {
        // Arrange
        $directory = $this->createFixtureDirectory();
        $outputFile = $directory . '/report.sarif';

        try {
            // Act
            $process = $this->runCli([
                '--path=' . $directory,
                '--format=sarif',
                '--output=' . $outputFile,
            ]);
            $document = json_decode(
                (string) file_get_contents($outputFile),
                true,
                512,
                JSON_THROW_ON_ERROR
            );

            // Assert
            self::assertSame(0, $process['exitCode']);
            self::assertSame([], $document['runs'][0]['invocations'][0]['toolExecutionNotifications'] ?? []);
            self::assertSame('', $process['stdout']);
            self::assertSame('2.1.0', $document['version']);
        } finally {
            $this->removeFixtureDirectory($directory);
        }
    }

    /**
     * Verify invalid formats and invalid output option combinations return errors.
     */
    public function testRejectsUnsupportedFormatAndTextOutputFile(): void
    {
        // Arrange
        $directory = $this->createFixtureDirectory();

        try {
            // Act
            $unsupported = $this->runCli([
                '--path=' . $directory,
                '--format=xml',
            ]);
            $textOutput = $this->runCli([
                '--path=' . $directory,
                '--output=' . $directory . '/report.txt',
            ]);

            // Assert
            self::assertSame(2, $unsupported['exitCode']);
            self::assertStringContainsString('Unsupported output format', $unsupported['stderr']);
            self::assertSame(2, $textOutput['exitCode']);
            self::assertStringContainsString('--output requires --format=sarif', $textOutput['stderr']);
        } finally {
            $this->removeFixtureDirectory($directory);
        }
    }

    /**
     * Verify text remains the default CLI output format.
     */
    public function testKeepsTextOutputAsDefault(): void
    {
        // Arrange
        $directory = $this->createFixtureDirectory();

        try {
            // Act
            $process = $this->runCli(['--path=' . $directory]);

            // Assert
            self::assertSame(0, $process['exitCode']);
            self::assertStringStartsWith('Scan results', $process['stdout']);
            self::assertStringNotContainsString('"version": "2.1.0"', $process['stdout']);
        } finally {
            $this->removeFixtureDirectory($directory);
        }
    }


    /**
     * Verify a failed report write returns an error without corrupting standard output.
     */
    public function testReportsSarifOutputFileWriteFailure(): void
    {
        // Arrange
        $directory = $this->createFixtureDirectory();
        $outputFile = $directory . '/missing/report.sarif';

        try {
            // Act
            $process = $this->runCli([
                '--path=' . $directory,
                '--format=sarif',
                '--output=' . $outputFile,
            ]);

            // Assert
            self::assertSame(3, $process['exitCode']);
            self::assertSame('', $process['stdout']);
            self::assertStringContainsString('Could not write SARIF report', $process['stderr']);
        } finally {
            $this->removeFixtureDirectory($directory);
        }
    }

    /** Execute the CLI with real arguments and return its process output.
     * @param string[] $arguments
     * @return array{exitCode: int, stdout: string, stderr: string}
     */
    private function runCli(array $arguments): array
    {
        $projectRoot = dirname(__DIR__, 2);
        $command = array_merge([PHP_BINARY, $projectRoot . '/bin/php-sl'], $arguments);
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $process = proc_open($command, $descriptors, $pipes, $projectRoot);

        self::assertIsResource($process);

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        return [
            'exitCode' => proc_close($process),
            'stdout' => $stdout === false ? '' : $stdout,
            'stderr' => $stderr === false ? '' : $stderr,
        ];
    }

    /** Create a temporary fixture containing a detectable vulnerability. */
    private function createFixtureDirectory(): string
    {
        $directory = sys_get_temp_dir() . '/php-sl-cli-' . bin2hex(random_bytes(5));
        self::assertTrue(mkdir($directory));
        self::assertNotFalse(
            file_put_contents($directory . '/unsafe.php', "<?php\nexec(\$_GET['command']);\n")
        );

        return $directory;
    }

    /** Remove the temporary fixture directory and its contents. */
    private function removeFixtureDirectory(string $directory): void
    {
        foreach (new \DirectoryIterator($directory) as $entry) {
            if ($entry->isFile() || $entry->isLink()) {
                unlink($entry->getPathname());
            }
        }

        rmdir($directory);
    }
}
