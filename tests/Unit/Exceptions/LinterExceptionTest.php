<?php

namespace Yousha\PhpSecurityLinter\Tests\Unit\Exceptions;

use Yousha\PhpSecurityLinter\Exceptions\LinterException;
use PHPUnit\Framework\TestCase;

/**
 * Class LinterExceptionTest
 *
 * This class contains unit tests forLinterException class,
 * ensuring that exceptions behave as expected with different parameters and use cases.
 */
final class LinterExceptionTest extends TestCase
{
    /**
     * Tests basic exception instantiation.
     *
     * - Ensures thatexception message and code are properly set.
     * - Confirms thatdefault context value is null.
     *
     * @return void
     */
    public function testBasicException(): void
    {
        $exception = new LinterException('Test message', 123);
        $this->assertEquals('Test message', $exception->getMessage());
        $this->assertEquals(123, $exception->getCode());
        $this->assertNull($exception->getContext());
    }

    /**
     * Tests exception instantiation with an additional context parameter.
     *
     * - Verifies thatcontext value is set correctly.
     * - Ensures thatexception string representation includescontext information.
     *
     * @return void
     */
    public function testExceptionWithContext(): void
    {
        $exception = new LinterException('Test message', 0, null, 'Additional context');
        $this->assertEquals('Additional context', $exception->getContext());
        $this->assertStringContainsString('Context: Additional context', (string) $exception);
    }

    /**
     * Testsfactory method for file access errors.
     *
     * - Verifies thatcorrect message and error code are assigned.
     * - Ensuresexception context provides meaningful instructions for debugging.
     *
     * @return void
     */
    public function testFileAccessErrorFactory(): void
    {
        $exception = LinterException::fileAccessError('/path/to/file.php');
        $this->assertEquals(
            'Could not access file: /path/to/file.php',
            $exception->getMessage()
        );
        $this->assertEquals(100, $exception->getCode());
        $this->assertEquals(
            'Check file permissions and existence',
            $exception->getContext()
        );
    }

    /**
     * Testsfactory method for parsing errors.
     *
     * - Confirms thaterror message containsfile path and description.
     * - Ensures thaterror code and context are correctly assigned.
     *
     * @return void
     */
    public function testParsingErrorFactory(): void
    {
        $exception = LinterException::parsingError('/path/to/file.php', 'Syntax error');
        $this->assertEquals(
            'Error parsing file /path/to/file.php: Syntax error',
            $exception->getMessage()
        );
        $this->assertEquals(200, $exception->getCode());
        $this->assertEquals(
            'Check file syntax and encoding',
            $exception->getContext()
        );
    }

    /**
     * Testsfactory method for invalid security rules.
     *
     * - Ensurescorrect error message and code are set for invalid rules.
     * - Confirms thatcontext provides guidance for resolving rule errors.
     *
     * @return void
     */
    public function testInvalidRuleFactory(): void
    {
        $exception = LinterException::invalidRule('bad_rule_pattern');
        $this->assertEquals(
            'Invalid security rule: bad_rule_pattern',
            $exception->getMessage()
        );
        $this->assertEquals(300, $exception->getCode());
        $this->assertEquals(
            'Check rule configuration and pattern validity',
            $exception->getContext()
        );
    }

    /**
     * Tests exception chaining to ensure that nested exceptions are handled properly.
     *
     * - Creates a LinterException with a previous exception.
     * - Verifies thatoriginal exception is correctly linked.
     *
     * @return void
     */
    public function testExceptionChaining(): void
    {
        $previous = new \RuntimeException('Previous error');
        $exception = new LinterException('Wrapper error', 0, $previous);
        $this->assertSame($previous, $exception->getPrevious());
    }
}
