<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests {

    use Exception;
    use RuntimeException;
    use stdClass;
    use PHPUnit\Framework\TestCase;

    #[\PHPUnit\Framework\Attributes\Group('Environment')]
    #[\PHPUnit\Framework\Attributes\Medium]
    final class EnvironmentTest extends TestCase
    {
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
            // Methods initialization codes.
        }

        /** Release resources created by each test. */
        #[\PHPUnit\Framework\Attributes\DoesNotPerformAssertions]
        protected function tearDown(): void
        {
            // Methods finalization codes.
            parent::tearDown();
        }

        /** Verify  php_1 behavior. */
        #[\PHPUnit\Framework\Attributes\Test]
        final public function testPhp_1(): void
        {
                    // Arrange
// Assert
        // Assert
        
            $this->assertTrue(true);

            // Assert
        // Assert
        
            $this->assertFalse(false);

            // Assert
        // Assert
        
            $this->assertNull(null);

            // Assert
        // Assert
        
            $this->assertIsObject(new stdClass());

            // Assert
        // Assert
        
            $this->assertSame(1, 1);

            // Assert
        // Assert
        
            $this->assertSame('A', 'A');

            // Assert
        // Assert
        
            $this->assertNotSame(1, '1');

            // Assert
        // Assert
        
            $this->assertEquals(1, '1');

            // Assert
        // Assert
        
            $this->assertNotEquals(1, -1);

            // Assert
        // Assert
        
            $this->assertNotEquals('A', '');

            // Arrange
            $testString = '1234567890';
            // Action
            $result = stristr($testString, 'abc');
            // Assert
        // Assert
        
            $this->assertFalse($result);
            // Action
            $result = stristr($testString, '567');
            // Assert
        // Assert
        
            $this->assertSame('567890', $result);

            // Assert
        // Assert
        
            $this->assertNotEmpty(php_uname());

            // Assert
        // Assert
        
            $this->assertSame(min(3, 4, 2, 8, 10), 2);

            // Arrange
            $testVar = 'Test.';
            // Act
        // Assert
        
            $this->assertIsString($testVar);
        }


        /** Verify  php_1 behavior. */
        #[\PHPUnit\Framework\Attributes\Test]
        final public function testPhp_2(): void
        {
                    // Arrange
        // Assert
        
$this->assertNotEmpty(getmypid());

            // Assert
        // Assert
        
            $this->assertTrue(extension_loaded('standard'));

            // Assert
        // Assert
        
            $this->assertTrue(extension_loaded('Core'));

            // Assert
        // Assert
        
            $this->assertNotEmpty(PHP_OS);

            // Assert
        // Assert
        
            $this->assertNotEmpty(PHP_MAJOR_VERSION);

            // Assert
        // Assert
        
            $this->assertNotEmpty(PHP_MINOR_VERSION);

            // Act
            $result = hash('sha256', '1234567890Abcdefg');
            // Assert
        // Assert
        
            $this->assertSame('acb7c749f0da6d3b87c1265856a590067c268a1843976f38f4223c5ccfe92d25', $result);

            // Assert
        // Assert
        
            $this->assertNotEmpty(get_loaded_extensions());

            // Act
            if (PHP_MAJOR_VERSION == 5) {
                // Assert
        // Assert
        
                $this->assertSame(PHP_INT_MAX, 2147483647);
            } else {
                // Assert
        // Assert
        
                $this->assertSame(PHP_INT_MAX, 9223372036854775807);
            }

            // Arrange
            $testArray = [];
            // Act
        // Assert
        
            $this->assertSame([], $testArray);
            unset($testArray);
        // Assert
        
            $this->assertFalse(isset($testArray));

            // Assert
        // Assert
        
            $this->assertTrue(isset($_SERVER['SCRIPT_NAME']));

            // Arrange
            $_SERVER['SCRIPT_NAME'] = 'a/b/c/test.php';
            // Act
        // Assert
        
            $this->assertSame('a/b/c/test.php', $_SERVER['SCRIPT_NAME']);

            // Arrange
            $_SERVER['HTTPS'] = '1';
            // Act
        // Assert
        
            $this->assertSame('1', $_SERVER['HTTPS']);

            // Assert
        // Assert
        
            $this->assertTrue(putenv('NAME=Test'));

            // Assert
        // Assert
        
            $this->assertSame('Test', getenv('NAME'));

            // Arrange
            $_SERVER['TEST'] = 'a';
            // Act
        // Assert
        
            $this->assertSame('a', $_SERVER['TEST']);

            // Assert
        // Assert
        
            $this->assertGreaterThan(0, time());

            // Arrange
            ob_start();
            // Action
            $result = ob_get_clean();
            // Arrange
        // Assert
        
            $this->assertEmpty($result);

            // Arrange
            ob_start();
            echo 'Test data.';
            // Action
            $result = ob_get_clean();
            // Assert
        // Assert
        
            $this->assertSame('Test data.', $result);

            // Arrange
            ob_start();
            echo '<div class="test" style="direction: ltr;">Test data.</div>';
            // Action
            $result = ob_get_clean();
            // Assert
        // Assert
        
            $this->assertSame('<div class="test" style="direction: ltr;">Test data.</div>', $result);

            // Arrange
            $message = 'Test message.';
            // Assert
            $exceptionObject = new RuntimeException($message);
            // Action
        // Assert
        
            $this->assertInstanceOf(Exception::class, $exceptionObject);
        // Assert
        
            $this->assertInstanceOf(RuntimeException::class, $exceptionObject);
        // Assert
        
            $this->assertSame($message, $exceptionObject->getMessage());

            // Assert
        // Act
        
            $this->expectException(RuntimeException::class);
            throw new RuntimeException(''); //NOSONAR
            $this->fail('Failed asserting that `RuntimeException` thrown.'); //NOSONAR
        }
    }
}
