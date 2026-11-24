<?php

namespace Yousha\PhpSecurityLinter\Tests\Unit;

use Yousha\PhpSecurityLinter\Linter;
use Yousha\PhpSecurityLinter\Exceptions\LinterException;
use PHPUnit\Framework\TestCase;

/**
 * Class LinterTest
 *
 * This class contains unit tests forLinter class, ensuring that
 * it correctly detects security vulnerabilities, handles exclusions,
 * and raises exceptions for invalid paths.
 */
#[\PHPUnit\Framework\Attributes\Small]
final class LinterTest extends TestCase
{
    private Linter $linter;

    /**
     * This method is called before the first test method in the test class is executed.
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\DoesNotPerformAssertions]
    public static function setUpBeforeClass(): void {}

    /**
     * This method is called after the last test method in the test class has been executed.
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\DoesNotPerformAssertions]
    public static function tearDownAfterClass(): void
    {
        gc_collect_cycles();
    }

    /**
     * This method is called BEFORE each test method.
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\DoesNotPerformAssertions]
    protected function setUp(): void
    {
        parent::setUp();
        $this->linter = new Linter();
    }

    /**
     * This method is called AFTER each test method.
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\DoesNotPerformAssertions]
    protected function tearDown(): void
    {
        // Methods finalization codes.
        parent::tearDown();
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testClassIsFinal(): void
    {
        // Arrange
        $reflection = new \ReflectionClass(Linter::class);

        // Act & Assert
        $this->assertTrue($reflection->isFinal(), 'Linter class should be final');
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testClassHasCorrectNamespace(): void
    {
        // Act & Assert
        $this->assertStringStartsWith(
            'Yousha\PhpSecurityLinter',
            Linter::class,
            'Class should be in correct namespace'
        );
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testLinterInitializesWithRules(): void
    {
        // Arrange
        $reflection = new \ReflectionClass(Linter::class);
        $property = $reflection->getProperty('rules');

        // Act
        $rules = $property->getValue($this->linter);

        // Assert
        $this->assertIsArray($rules);
        $this->assertNotEmpty($rules);
        $firstRule = reset($rules);
        $this->assertArrayHasKey('pattern', $firstRule);
        $this->assertArrayHasKey('severity', $firstRule);
        $this->assertArrayHasKey('message', $firstRule);
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanMethodExists(): void
    {
        // Act & Assert
        $this->assertTrue(method_exists(Linter::class, 'scan'));
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanMethodSignature(): void
    {
        // Arrange
        $method = new \ReflectionMethod(Linter::class, 'scan');

        // Act
        $parameters = $method->getParameters();

        // Assert
        $this->assertEquals('array', $method->getReturnType()->getName());
        $this->assertCount(2, $parameters);
        $this->assertEquals('path', $parameters[0]->getName());
        $this->assertEquals('string', $parameters[0]->getType()->getName());
        $this->assertEquals('exclude', $parameters[1]->getName());
        $this->assertEquals('array', $parameters[1]->getType()->getName());
        $this->assertTrue($parameters[1]->isDefaultValueAvailable());
        $this->assertEquals([], $parameters[1]->getDefaultValue());
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanDirectoryWithNonPhpFiles(): void
    {
        // Arrange
        $tempDir = sys_get_temp_dir() . '/test_dir_' . uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir . '/test.txt', 'Not a PHP file');

        try {
            // Act
            $results = $this->linter->scan($tempDir);

            // Assert
            $this->assertSame(0, $results['_meta']['scanned_count']);
            $this->assertSame(0, $results['_meta']['warning_count']);
        } finally {
            unlink($tempDir . '/test.txt');
            rmdir($tempDir);
        }
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanReturnsMetadataWithFiles(): void
    {
        // Arrange
        $tempDir = sys_get_temp_dir() . '/test_dir_' . uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir . '/test.php', '<?php echo "test";');

        try {
            // Act
            $results = $this->linter->scan($tempDir);

            // Assert
            $this->assertArrayHasKey('_meta', $results);
            $this->assertEquals(1, $results['_meta']['scanned_count']);
        } finally {
            unlink($tempDir . '/test.php');
            rmdir($tempDir);
        }
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanThrowsExceptionForInvalidPath(): void
    {
        // Arrange
        $this->expectException(LinterException::class);
        $this->expectExceptionMessage('Path does not exist: /nonexistent/path');

        // Act
        $this->linter->scan('/nonexistent/path');
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testCanScanEmptyDirectory(): void
    {
        // Arrange
        $tempDir = sys_get_temp_dir() . '/empty_test_dir_' . uniqid();
        mkdir($tempDir);

        try {
            // Act
            $results = $this->linter->scan($tempDir);

            // Assert
            if (array_key_exists('_meta', $results)) {
                unset($results['_meta']);
            }
            $this->assertEmpty($results);
        } finally {
            if (is_dir($tempDir)) {
                rmdir($tempDir);
            }
        }
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testShouldExcludeMethodIsPrivate(): void
    {
        $method = new \ReflectionMethod(Linter::class, 'shouldExclude');
        $this->assertTrue($method->isPrivate());
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanFileMethodIsPrivate(): void
    {
        $method = new \ReflectionMethod(Linter::class, 'scanFile');
        $this->assertTrue($method->isPrivate());
    }

    /**
     *
     *
     * @return void
     */
    #[\PHPUnit\Framework\Attributes\Test]
    public function testInvalidDirectory(): void
    {
        $this->expectException(LinterException::class);
        $this->expectExceptionMessage('Path does not exist: /nonexistent/path');
        $linter = new Linter();
        $linter->scan('/nonexistent/path');
    }

    #[\PHPUnit\Framework\Attributes\Test]
    public function testScanMetadataIsPresentForEmptyDirectory(): void
    {
        $tempDir = sys_get_temp_dir() . '/scan_empty_' . uniqid();
        mkdir($tempDir);

        try {
            $results = $this->linter->scan($tempDir);

            $this->assertSame(0, $results['_meta']['scanned_count']);
            $this->assertSame(0, $results['_meta']['issue_count']);
            $this->assertSame(0, $results['_meta']['warning_count']);
            $this->assertSame([], $results['_meta']['warnings']);
        } finally {
            rmdir($tempDir);
        }
    }
}
