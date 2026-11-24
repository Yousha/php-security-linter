<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests\Unit\Reporting;

use PHPUnit\Framework\TestCase;
use Yousha\PhpSecurityLinter\Reporting\SarifFormatter;

/**
 * Tests SARIF 2.1.0 report serialization.
 */
#[\PHPUnit\Framework\Attributes\Small]
final class SarifFormatterTest extends TestCase
{
    /**
     * Verify finding metadata and its physical source location.
     */
    public function testFormatsFindingsAsSarif21(): void
    {
        // Arrange
        $formatter = new SarifFormatter();
        $root = sys_get_temp_dir() . '/php-sl-sarif-' . bin2hex(random_bytes(5));
        mkdir($root);
        $file = $root . '/unsafe.php';
        file_put_contents($file, "<?php\nexec(\$_GET['cmd']);\n");

        try {
            // Act
            $json = $formatter->format([
                $file => [[
                    'severity' => 'critical',
                    'message' => 'OWASP-002: OS Command Injection risk (exec/system with unsanitized input)',
                    'line' => 2,
                ]],
                '_meta' => [
                    'scanned_count' => 1,
                    'issue_count' => 1,
                    'warning_count' => 0,
                    'warnings' => [],
                ],
            ], $root);
            $document = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

            // Assert
            self::assertSame('2.1.0', $document['version']);
            self::assertCount(1, $document['runs']);
            self::assertSame('PHP Security Linter', $document['runs'][0]['tool']['driver']['name']);
            self::assertSame('OWASP-002', $document['runs'][0]['results'][0]['ruleId']);
            self::assertSame('error', $document['runs'][0]['results'][0]['level']);
            self::assertSame('unsafe.php', $document['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']);
            self::assertSame(2, $document['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine']);
            self::assertSame('A03:2021', $document['runs'][0]['results'][0]['properties']['standardReference']);
            self::assertTrue($document['runs'][0]['invocations'][0]['executionSuccessful']);
        } finally {
            unlink($file);
            rmdir($root);
        }
    }

    /**
     * Verify a scan with no findings produces an empty result set.
     */
    public function testFormatsCleanScanWithoutFindings(): void
    {
        // Arrange
        $formatter = new SarifFormatter();

        // Act
        $document = json_decode($formatter->format([
            '_meta' => [
                'scanned_count' => 0,
                'issue_count' => 0,
                'warning_count' => 0,
                'warnings' => [],
            ],
        ], sys_get_temp_dir()), true, 512, JSON_THROW_ON_ERROR);

        // Assert
        self::assertSame([], $document['runs'][0]['results']);
        self::assertTrue($document['runs'][0]['invocations'][0]['executionSuccessful']);
    }

    /**
     * Verify scan warnings are execution notifications, not vulnerability results.
     */
    public function testFormatsScanWarningsAsExecutionNotifications(): void
    {
        // Arrange
        $formatter = new SarifFormatter();

        // Act
        $document = json_decode($formatter->format([
            '_meta' => [
                'scanned_count' => 0,
                'issue_count' => 0,
                'warning_count' => 1,
                'warnings' => ['Could not read file: unreadable.php'],
            ],
        ], sys_get_temp_dir()), true, 512, JSON_THROW_ON_ERROR);

        // Assert
        self::assertSame([], $document['runs'][0]['results']);
        self::assertFalse($document['runs'][0]['invocations'][0]['executionSuccessful']);
        self::assertSame(
            'Could not read file: unreadable.php',
            $document['runs'][0]['invocations'][0]['toolExecutionNotifications'][0]['message']['text']
        );
    }
}
