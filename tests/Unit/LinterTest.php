<?php

namespace Yousha\PhpSecurityLinter\Tests\Unit;

use Yousha\PhpSecurityLinter\Linter;
use Yousha\PhpSecurityLinter\Exceptions\LinterException;
use PHPUnit\Framework\TestCase;

/** Initialize shared test fixtures before the test class runs. */
    #[\PHPUnit\Framework\Attributes\DoesNotPerformAssertions]
    public static function setUpBeforeClass(): void {}

    /** Release shared resources after the test class finishes. */
    #[\PHPUnit\Framework\Attributes\DoesNotPerformAssertions]
    public static function tearDownAfterClass(): void
    {
        gc_collect_cycles();
    }

    /** Initialize resources required by each test. */
    #[\PHPUnit\Framework\Attributes\DoesNotPerformAssertions]
    protected function setUp(): void
    {
        parent::setUp();
        $this->linter = new Linter();
    }

    /** Release resources created by each test. */
    #[\PHPUnit\Framework\Attributes\DoesNotPerformAssertions]
    protected function tearDown(): void
    {
        // Methods finalization codes.
        parent::tearDown();
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testClassIsFinal(): void
    {
                // Arrange
$reflection = new \ReflectionClass(Linter::class);
        // Assert
        
        $this->assertTrue($reflection->isFinal(), 'Linter class should be final');
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testClassHasCorrectNamespace(): void
    {
                // Arrange
        // Assert
        
$this->assertStringStartsWith(
            'Yousha\PhpSecurityLinter',
            Linter::class,
            'Class should be in correct namespace'
        );
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testLinterInitializesWithRules(): void
    {
                // Arrange
$reflection = new \ReflectionClass(Linter::class);
        $property = $reflection->getProperty('rules');
        $rules = $property->getValue($this->linter);
        // Assert
        
        $this->assertIsArray($rules);
        // Assert
        
        $this->assertNotEmpty($rules);
        // Check some sample rule structure.
        $firstRule = reset($rules);
        // Assert
        
        $this->assertArrayHasKey('pattern', $firstRule);
        // Assert
        
        $this->assertArrayHasKey('severity', $firstRule);
        // Assert
        
        $this->assertArrayHasKey('message', $firstRule);
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanMethodExists(): void
    {
                // Arrange
        // Assert
        
$this->assertTrue(
            method_exists(Linter::class, 'scan')
        );
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanMethodSignature(): void
    {
                // Arrange
$method = new \ReflectionMethod(Linter::class, 'scan');
        // Assert
        

        $this->assertEquals(
            'array',
            $method->getReturnType()->getName()
        );

        $parameters = $method->getParameters();
        // Assert
        
        $this->assertCount(2, $parameters);
        // Assert
        

        $this->assertEquals('path', $parameters[0]->getName());
        // Assert
        
        $this->assertEquals('string', $parameters[0]->getType()->getName());
        // Assert
        

        $this->assertEquals('exclude', $parameters[1]->getName());
        // Assert
        
        $this->assertEquals('array', $parameters[1]->getType()->getName());
        // Assert
        
        $this->assertTrue($parameters[1]->isDefaultValueAvailable());
        // Assert
        
        $this->assertEquals([], $parameters[1]->getDefaultValue());
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanDirectoryWithNonPhpFiles(): void
    {
                // Arrange
$tempDir = sys_get_temp_dir() . '/test_dir_' . uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir . '/test.txt', 'Not a PHP file');

        try {
            $results = $this->linter->scan($tempDir);
        // Assert
        
            $this->assertSame(0, $results['_meta']['scanned_count']);
        // Assert
        
            $this->assertSame(0, $results['_meta']['warning_count']);
        } finally {
            unlink($tempDir . '/test.txt');
            rmdir($tempDir);
        }
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanReturnsMetadataWithFiles(): void
    {
                // Arrange
// Create temp dir with sample PHP file
        $tempDir = sys_get_temp_dir() . '/test_dir_' . uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir . '/test.php', '<?php echo "test";');

        try {
            $results = $this->linter->scan($tempDir);
        // Assert
        
            $this->assertArrayHasKey('_meta', $results);
        // Assert
        
            $this->assertEquals(1, $results['_meta']['scanned_count']);
        } finally {
            unlink($tempDir . '/test.php');
            rmdir($tempDir);
        }
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanThrowsExceptionForInvalidPath(): void
    {
                // Arrange
        // Act
        
$this->expectException(LinterException::class);
        // Act
        
        $this->expectExceptionMessage('Path does not exist: /nonexistent/path');

        $this->linter->scan('/nonexistent/path');
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testCanScanEmptyDirectory(): void
    {
                // Arrange
$tempDir = sys_get_temp_dir() . '/empty_test_dir_' . uniqid();
        mkdir($tempDir);

        try {
            $results = $this->linter->scan($tempDir);

            // Remove metadata if present
            if (array_key_exists('_meta', $results)) {
                unset($results['_meta']);
            }
        // Assert
        

            $this->assertEmpty($results);
        } finally {
            // Cleanup in finally block to ensure it runs even if test fails
            if (is_dir($tempDir)) {
                rmdir($tempDir);
            }
        }
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testShouldExcludeMethodIsPrivate(): void
    {
                // Arrange
$method = new \ReflectionMethod(Linter::class, 'shouldExclude');
        // Assert
        
        $this->assertTrue($method->isPrivate());
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanFileMethodIsPrivate(): void
    {
                // Arrange
$method = new \ReflectionMethod(Linter::class, 'scanFile');
        // Assert
        
        $this->assertTrue($method->isPrivate());
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testInvalidDirectory(): void
    {
                // Arrange
        // Act
        
$this->expectException(LinterException::class);
        // Act
        
        $this->expectExceptionMessage('Path does not exist: /nonexistent/path');
        $linter = new Linter();
        $linter->scan('/nonexistent/path');
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanMetadataIsPresentForEmptyDirectory(): void
    {
                // Arrange
$tempDir = sys_get_temp_dir() . '/scan_empty_' . uniqid();
        mkdir($tempDir);

        try {
            $results = $this->linter->scan($tempDir);
        // Assert
        

            $this->assertSame(0, $results['_meta']['scanned_count']);
        // Assert
        
            $this->assertSame(0, $results['_meta']['issue_count']);
        // Assert
        
            $this->assertSame(0, $results['_meta']['warning_count']);
        // Assert
        
            $this->assertSame([], $results['_meta']['warnings']);
        } finally {
            rmdir($tempDir);
        }
    }
}
