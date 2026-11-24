<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests\Unit\Exceptions;

use Yousha\PhpSecurityLinter\Exceptions\LinterException;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for LinterException.
 */
final class LinterExceptionTest extends TestCase
{
    public function testBasicException(): void
    {
        // Arrange
        $message = 'Test message';
        $code = 123;

        // Act
        $exception = new LinterException($message, $code);

        // Assert
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertNull($exception->getContext());
    }

    public function testExceptionWithContext(): void
    {
        // Arrange
        $context = 'Additional context';

        // Act
        $exception = new LinterException('Test message', 0, null, $context);

        // Assert
        $this->assertEquals($context, $exception->getContext());
        $this->assertStringContainsString('Context: ' . $context, (string) $exception);
    }

    public function testFileAccessErrorFactory(): void
    {
        // Arrange
        $path = '/path/to/file.php';

        // Act
        $exception = LinterException::fileAccessError($path);

        // Assert
        $this->assertEquals('Could not access file: ' . $path, $exception->getMessage());
        $this->assertEquals(100, $exception->getCode());
        $this->assertEquals('Check file permissions and existence', $exception->getContext());
    }

    public function testParsingErrorFactory(): void
    {
        // Arrange
        $path = '/path/to/file.php';
        $error = 'Syntax error';

        // Act
        $exception = LinterException::parsingError($path, $error);

        // Assert
        $this->assertStringContainsString($path, $exception->getMessage());
        $this->assertStringContainsString($error, $exception->getMessage());
        $this->assertEquals(200, $exception->getCode());
        $this->assertEquals('Check file syntax and encoding', $exception->getContext());
    }

    public function testInvalidRuleFactory(): void
    {
        // Arrange
        $rule = 'bad-rule';

        // Act
        $exception = LinterException::invalidRule($rule);

        // Assert
        $this->assertStringContainsString($rule, $exception->getMessage());
        $this->assertEquals(300, $exception->getCode());
        $this->assertEquals('Check rule configuration and pattern validity', $exception->getContext());
    }

    public function testExceptionChaining(): void
    {
        // Arrange
        $previous = new \RuntimeException('root cause');

        // Act
        $exception = new LinterException('wrapper', 0, $previous);

        // Assert
        $this->assertSame($previous, $exception->getPrevious());
    }
}
