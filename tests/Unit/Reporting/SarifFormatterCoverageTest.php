<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests\Unit\Reporting;

use PHPUnit\Framework\TestCase;
use Yousha\PhpSecurityLinter\Reporting\SarifFormatter;
use ReflectionClass;

/**
 * Additional coverage for private methods in SarifFormatter.
 * Follows AAA pattern; no mocks.
 */
final class SarifFormatterCoverageTest extends TestCase
{
    /**
     * Test getVersion fallback when VERSION.txt is missing or empty.
     */
    public function testGetVersionFallbackToDev(): void
    {
        // Arrange
        $formatter = new SarifFormatter();
        $reflection = new ReflectionClass($formatter);
        $method = $reflection->getMethod('getVersion');
        if (PHP_VERSION_ID < 80100) {
            $method->setAccessible(true);
        }

        $originalVersionFile = dirname(__DIR__, 3) . '/VERSION.txt';
        $backup = $originalVersionFile . '.bak';

        // Temporarily rename VERSION.txt if it exists
        $hadFile = is_file($originalVersionFile);
        if ($hadFile) {
            rename($originalVersionFile, $backup);
        }

        try {
            // Act
            $version = $method->invoke($formatter);

            // Assert
            $this->assertSame('dev', $version);
        } finally {
            if ($hadFile) {
                rename($backup, $originalVersionFile);
            }
        }
    }

    /**
     * Test referenceUri returns null for non-OWASP references and correct URI for Axx.
     */
    public function testReferenceUriMapping(): void
    {
        // Arrange
        $formatter = new SarifFormatter();
        $reflection = new ReflectionClass($formatter);
        $method = $reflection->getMethod('referenceUri');
        if (PHP_VERSION_ID < 80100) {
            $method->setAccessible(true);
        }

        // Act & Assert
        $this->assertNull($method->invoke($formatter, null));
        $this->assertNull($method->invoke($formatter, 'CIS-001'));
        $this->assertSame(
            'https://owasp.org/Top10/A03_2021/',
            $method->invoke($formatter, 'A03:2021')
        );
    }

    /**
     * Test findRuleId returns null when message does not match any rule.
     */
    public function testFindRuleIdReturnsNullForUnknownMessage(): void
    {
        // Arrange
        $formatter = new SarifFormatter();
        $reflection = new ReflectionClass($formatter);
        $getRules = $reflection->getMethod('getRules');
        $findRuleId = $reflection->getMethod('findRuleId');
        if (PHP_VERSION_ID < 80100) {
            $getRules->setAccessible(true);
            $findRuleId->setAccessible(true);
        }

        $rules = $getRules->invoke($formatter);

        // Act
        $result = $findRuleId->invoke($formatter, 'This message does not exist', $rules);

        // Assert
        $this->assertNull($result);
    }

    /**
     * Test toArtifactUri when file is outside scan root (fallback to absolute).
     */
    public function testToArtifactUriOutsideRoot(): void
    {
        // Arrange
        $formatter = new SarifFormatter();
        $reflection = new ReflectionClass($formatter);
        $method = $reflection->getMethod('toArtifactUri');
        if (PHP_VERSION_ID < 80100) {
            $method->setAccessible(true);
        }

        $temporaryDirectory = sys_get_temp_dir();
        $suffix = uniqid('', true);
        $root = $temporaryDirectory . DIRECTORY_SEPARATOR . 'php-sl-sarif-root-' . $suffix;
        $outside = $temporaryDirectory . DIRECTORY_SEPARATOR . 'outside-' . $suffix . '.php';
        $this->assertTrue(mkdir($root));
        $this->assertNotFalse(file_put_contents($outside, '<?php'));

        try {
            // Act
            $uri = $method->invoke($formatter, $outside, $root);

            // Assert
            $this->assertStringContainsString('outside-', $uri);
        } finally {
            unlink($outside);
            rmdir($root);
        }
    }
}
