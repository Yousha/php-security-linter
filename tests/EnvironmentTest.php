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

        /** Verify basic PHP runtime functions and values. */
        #[\PHPUnit\Framework\Attributes\Test]
        final public function testPhp_1(): void
        {
        // Arrange

        // Act

        // Assert
            $this->assertTrue(true);
            $this->assertFalse(false);
            $this->assertNull(null);
            $this->assertIsObject(new stdClass());
            $this->assertSame(1, 1);
            $this->assertSame('A', 'A');
            $this->assertNotSame(1, '1');
            $this->assertEquals(1, '1');
            $this->assertNotEquals(1, -1);
            $this->assertNotEquals('A', '');
            $testString = '1234567890';
            $result = stristr($testString, 'abc');
            $this->assertFalse($result);
            $result = stristr($testString, '567');
            $this->assertSame('567890', $result);
            $this->assertNotEmpty(php_uname());
            $this->assertSame(min(3, 4, 2, 8, 10), 2);
            $testVar = 'Test.';
            $this->assertIsString($testVar);
        }


        /** Verify basic PHP runtime functions and values. */
        #[\PHPUnit\Framework\Attributes\Test]
        final public function testPhp_2(): void
        {
        // Arrange

        // Act

        // Assert
$this->assertNotEmpty(getmypid());
            $this->assertTrue(extension_loaded('standard'));
            $this->assertTrue(extension_loaded('Core'));
            $this->assertNotEmpty(PHP_OS);
            $this->assertNotEmpty(PHP_MAJOR_VERSION);
            $this->assertNotEmpty(PHP_MINOR_VERSION);
            $result = hash('sha256', '1234567890Abcdefg');
            $this->assertSame('acb7c749f0da6d3b87c1265856a590067c268a1843976f38f4223c5ccfe92d25', $result);
            $this->assertNotEmpty(get_loaded_extensions());
            if (PHP_MAJOR_VERSION == 5) {
                $this->assertSame(PHP_INT_MAX, 2147483647);
            } else {
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
