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

        // Act

        // Assert
        $this->assertTrue($reflection->isFinal(), 'Linter class should be final');
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testClassHasCorrectNamespace(): void
    {
        // Arrange

        // Act

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

        // Act

        // Assert
        $this->assertIsArray($rules);
        $this->assertNotEmpty($rules);
        // Check some sample rule structure.
        $firstRule = reset($rules);
        $this->assertArrayHasKey('pattern', $firstRule);
        $this->assertArrayHasKey('severity', $firstRule);
        $this->assertArrayHasKey('message', $firstRule);
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanMethodExists(): void
    {
        // Arrange

        // Act

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

        // Act

        // Assert
        $this->assertEquals(
            'array',
            $method->getReturnType()->getName()
        );
        $parameters = $method->getParameters();
        $this->assertCount(2, $parameters);
        $this->assertEquals('path', $parameters[0]->getName());
        $this->assertEquals('string', $parameters[0]->getType()->getName());
        $this->assertEquals('exclude', $parameters[1]->getName());
        $this->assertEquals('array', $parameters[1]->getType()->getName());
        $this->assertTrue($parameters[1]->isDefaultValueAvailable());
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

        // Act

        // Assert
            $this->assertSame(0, $results['_meta']['scanned_count']);
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

        // Act

        // Assert
            $this->assertArrayHasKey('_meta', $results);
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

        // Assert
$this->expectException(LinterException::class);
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

        // Act

        // Assert
        $this->assertTrue($method->isPrivate());
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanFileMethodIsPrivate(): void
    {
        // Arrange
$method = new \ReflectionMethod(Linter::class, 'scanFile');

        // Act

        // Assert
        $this->assertTrue($method->isPrivate());
    }

    /** Verify  class is final behavior. */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testInvalidDirectory(): void
    {
        // Arrange

        // Act

        // Assert
$this->expectException(LinterException::class);
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

        // Act

        // Assert
            $this->assertSame(0, $results['_meta']['scanned_count']);
            $this->assertSame(0, $results['_meta']['issue_count']);
            $this->assertSame(0, $results['_meta']['warning_count']);
            $this->assertSame([], $results['_meta']['warnings']);
        } finally {
            rmdir($tempDir);
        }
    }
}
