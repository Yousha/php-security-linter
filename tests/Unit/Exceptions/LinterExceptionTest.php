<?php

namespace Yousha\PhpSecurityLinter\Tests\Unit\Exceptions;

use Yousha\PhpSecurityLinter\Exceptions\LinterException;
use PHPUnit\Framework\TestCase;

/** Class LinterExceptionTest */
    public function testBasicException(): void
    {
                // Arrange
$exception = new LinterException('Test message', 123);
        // Assert
        
        $this->assertEquals('Test message', $exception->getMessage());
        // Assert
        
        $this->assertEquals(123, $exception->getCode());
        // Assert
        
        $this->assertNull($exception->getContext());
    }

    /** Tests exception instantiation with an additional context parameter. */
    public function testExceptionWithContext(): void
    {
                // Arrange
$exception = new LinterException('Test message', 0, null, 'Additional context');
        // Assert
        
        $this->assertEquals('Additional context', $exception->getContext());
        // Assert
        
        $this->assertStringContainsString('Context: Additional context', (string) $exception);
    }

    /** Testsfactory method for file access errors. */
    public function testFileAccessErrorFactory(): void
    {
                // Arrange
$exception = LinterException::fileAccessError('/path/to/file.php');
        // Assert
        
        $this->assertEquals(
            'Could not access file: /path/to/file.php',
            $exception->getMessage()
        );
        // Assert
        
        $this->assertEquals(100, $exception->getCode());
        // Assert
        
        $this->assertEquals(
            'Check file permissions and existence',
            $exception->getContext()
        );
    }

    /** Testsfactory method for parsing errors. */
    public function testParsingErrorFactory(): void
    {
                // Arrange
$exception = LinterException::parsingError('/path/to/file.php', 'Syntax error');
        // Assert
        
        $this->assertEquals(
            'Error parsing file /path/to/file.php: Syntax error',
            $exception->getMessage()
        );
        // Assert
        
        $this->assertEquals(200, $exception->getCode());
        // Assert
        
        $this->assertEquals(
            'Check file syntax and encoding',
            $exception->getContext()
        );
    }

    /** Testsfactory method for invalid security rules. */
    public function testInvalidRuleFactory(): void
    {
                // Arrange
$exception = LinterException::invalidRule('bad_rule_pattern');
        // Assert
        
        $this->assertEquals(
            'Invalid security rule: bad_rule_pattern',
            $exception->getMessage()
        );
        // Assert
        
        $this->assertEquals(300, $exception->getCode());
        // Assert
        
        $this->assertEquals(
            'Check rule configuration and pattern validity',
            $exception->getContext()
        );
    }

    /** Tests exception chaining to ensure that nested exceptions are handled properly. */
    public function testExceptionChaining(): void
    {
                // Arrange
$previous = new \RuntimeException('Previous error');
        $exception = new LinterException('Wrapper error', 0, $previous);
        // Assert
        
        $this->assertSame($previous, $exception->getPrevious());
    }
}
