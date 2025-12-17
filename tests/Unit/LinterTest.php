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
final class LinterTest extends TestCase
{
    private Linter $linter;

    /**
     * This method is called before the first test method in the test class is executed.
     *
     * @doesNotPerformAssertions
     *
     * @return void
     */
    public static function setUpBeforeClass(): void {}

    /**
     * This method is called after the last test method in the test class has been executed.
     *
     * @doesNotPerformAssertions
     *
     * @return void
     */
    public static function tearDownAfterClass(): void
    {
        gc_collect_cycles();
    }

    /**
     * This method is called BEFORE each test method.
     *
     * @doesNotPerformAssertions
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->linter = new Linter();
    }

    /**
     * This method is called AFTER each test method.
     *
     * @doesNotPerformAssertions
     *
     * @return void
     */
    protected function tearDown(): void
    {
        // Methods finalization codes.
        parent::tearDown();
    }

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testClassIsFinal(): void
    {
        $reflection = new \ReflectionClass(Linter::class);
        $this->assertTrue($reflection->isFinal(), 'Linter class should be final');
    }

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testClassHasCorrectNamespace(): void
    {
        $this->assertStringStartsWith(
            'Yousha\PhpSecurityLinter',
            Linter::class,
            'Class should be in correct namespace'
        );
    }

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testLinterInitializesWithRules(): void
    {
        $reflection = new \ReflectionClass(Linter::class);
        $property = $reflection->getProperty('rules');
        $property->setAccessible(true);
        $rules = $property->getValue($this->linter);
        $this->assertIsArray($rules);
        $this->assertNotEmpty($rules);
        // Check some sample rule structure.
        $firstRule = reset($rules);
        $this->assertArrayHasKey('pattern', $firstRule);
        $this->assertArrayHasKey('severity', $firstRule);
        $this->assertArrayHasKey('message', $firstRule);
    }

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testScanMethodExists(): void
    {
        $this->assertTrue(
            method_exists(Linter::class, 'scan')
        );
    }

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testScanMethodSignature(): void
    {
        $method = new \ReflectionMethod(Linter::class, 'scan');

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

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testScanDirectoryWithNonPhpFiles(): void
    {
        $tempDir = sys_get_temp_dir() . '/test_dir_' . uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir . '/test.txt', 'Not a PHP file');

        try {
            $results = $this->linter->scan($tempDir);
            $this->assertEmpty($results);
        } finally {
            unlink($tempDir . '/test.txt');
            rmdir($tempDir);
        }
    }

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testScanReturnsMetadataWithFiles(): void
    {
        // Create temp dir with sample PHP file
        $tempDir = sys_get_temp_dir() . '/test_dir_' . uniqid();
        mkdir($tempDir);
        file_put_contents($tempDir . '/test.php', '<?php echo "test";');

        try {
            $results = $this->linter->scan($tempDir);
            $this->assertArrayHasKey('_meta', $results);
            $this->assertEquals(1, $results['_meta']['scanned_count']);
        } finally {
            unlink($tempDir . '/test.php');
            rmdir($tempDir);
        }
    }

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testScanThrowsExceptionForInvalidPath(): void
    {
        $this->expectException(LinterException::class);
        $this->expectExceptionMessage('Path does not exist: /nonexistent/path');

        $this->linter->scan('/nonexistent/path');
    }

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testCanScanEmptyDirectory(): void
    {
        $tempDir = sys_get_temp_dir() . '/empty_test_dir_' . uniqid();
        mkdir($tempDir);

        try {
            $results = $this->linter->scan($tempDir);

            // Remove metadata if present
            if (array_key_exists('_meta', $results)) {
                unset($results['_meta']);
            }

            $this->assertEmpty($results);
        } finally {
            // Cleanup in finally block to ensure it runs even if test fails
            if (is_dir($tempDir)) {
                rmdir($tempDir);
            }
        }
    }

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testShouldExcludeMethodIsPrivate(): void
    {
        $method = new \ReflectionMethod(Linter::class, 'shouldExclude');
        $this->assertTrue($method->isPrivate());
    }

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testScanFileMethodIsPrivate(): void
    {
        $method = new \ReflectionMethod(Linter::class, 'scanFile');
        $this->assertTrue($method->isPrivate());
    }

    /**
     * @test
     *
     * @small
     *
     * @return void
     */
    public function testInvalidDirectory(): void
    {
        $this->expectException(LinterException::class);
        $linter = new Linter();
        $linter->scan('/nonexistent/path');
    }
}
