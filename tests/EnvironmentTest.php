<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests {

    use Exception;
    use RuntimeException;
    use stdClass;
    use PHPUnit\Framework\TestCase;

    /**
     * @group Environment
     */
    final class EnvironmentTest extends TestCase
    {
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
            // Methods initialization codes.
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
         * @medium
         *
         * @return void
         */
        final public function testPhp_1(): void
        {
            // AAA
            $this->assertTrue(true);

            // AAA
            $this->assertFalse(false);

            // AAA
            $this->assertNull(null);

            // AAA
            $this->assertIsObject(new stdClass());

            // AAA
            $this->assertSame(1, 1);

            // AAA
            $this->assertSame('A', 'A');

            // AAA
            $this->assertNotSame(1, '1');

            // AAA
            $this->assertEquals(1, '1');

            // AAA
            $this->assertNotEquals(1, -1);

            // AAA
            $this->assertNotEquals('A', '');

            // Arrange
            $testString = '1234567890';
            // Action
            $result = stristr($testString, 'abc');
            // Assert
            $this->assertFalse($result);
            // Action
            $result = stristr($testString, '567');
            // Assert
            $this->assertSame('567890', $result);

            // AAA
            $this->assertNotEmpty(php_uname());

            // AAA
            $this->assertSame(min(3, 4, 2, 8, 10), 2);

            // Arrange
            $testVar = 'Test.';
            // Action/Assert
            $this->assertIsString($testVar);
        }


        /**
         * @test
         *
         * @medium
         *
         * @return void
         */
        final public function testPhp_2(): void
        {
            $this->assertNotEmpty(getmypid());

            // AAA
            $this->assertTrue(extension_loaded('standard'));

            // AAA
            $this->assertTrue(extension_loaded('Core'));

            // AAA
            $this->assertNotEmpty(PHP_OS);

            // AAA
            $this->assertNotEmpty(PHP_MAJOR_VERSION);

            // AAA
            $this->assertNotEmpty(PHP_MINOR_VERSION);

            // Arrange/Action
            $result = hash('sha256', '1234567890Abcdefg');
            // Assert
            $this->assertSame('acb7c749f0da6d3b87c1265856a590067c268a1843976f38f4223c5ccfe92d25', $result);

            // AAA
            $this->assertNotEmpty(get_loaded_extensions());

            // Arrange/Action
            if (PHP_MAJOR_VERSION == 5) {
                // Assert
                $this->assertSame(PHP_INT_MAX, 2147483647);
            } else {
                // Assert
                $this->assertSame(PHP_INT_MAX, 9223372036854775807);
            }

            // Arrange
            $testArray = [];
            // Action/Assert
            $this->assertSame([], $testArray);
            unset($testArray);
            $this->assertFalse(isset($testArray));

            // AAA
            $this->assertTrue(isset($_SERVER['SCRIPT_NAME']));

            // Arrange
            $_SERVER['SCRIPT_NAME'] = 'a/b/c/test.php';
            // Arrange/Action
            $this->assertSame('a/b/c/test.php', $_SERVER['SCRIPT_NAME']);

            // Arrange
            $_SERVER['HTTPS'] = '1';
            // Arrange/Action
            $this->assertSame('1', $_SERVER['HTTPS']);

            // AAA
            $this->assertTrue(putenv('NAME=Test'));

            // AAA
            $this->assertSame('Test', getenv('NAME'));

            // Arrange
            $_SERVER['TEST'] = 'a';
            // Action/Assert
            $this->assertSame('a', $_SERVER['TEST']);

            // AAA
            $this->assertGreaterThan(0, time());

            // Arrange
            ob_start();
            // Action
            $result = ob_get_clean();
            // Arrange
            $this->assertEmpty($result);

            // Arrange
            ob_start();
            echo 'Test data.';
            // Action
            $result = ob_get_clean();
            // Assert
            $this->assertSame('Test data.', $result);

            // Arrange
            ob_start();
            echo '<div class="test" style="direction: ltr;">Test data.</div>';
            // Action
            $result = ob_get_clean();
            // Assert
            $this->assertSame('<div class="test" style="direction: ltr;">Test data.</div>', $result);

            // Arrange
            $message = 'Test message.';
            // Assert
            $exceptionObject = new RuntimeException($message);
            // Action
            $this->assertInstanceOf(Exception::class, $exceptionObject);
            $this->assertInstanceOf(RuntimeException::class, $exceptionObject);
            $this->assertSame($message, $exceptionObject->getMessage());

            // AAA
            $this->expectException(RuntimeException::class);
            throw new RuntimeException(''); //NOSONAR
            $this->fail('Failed asserting that `RuntimeException` thrown.'); //NOSONAR
        }
    }
}
