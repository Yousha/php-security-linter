<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests {

    use Throwable;
    use PHPUnit\Framework\TestCase;
    use Yousha\PhpSecurityLinter\Linter;

    /**
     * @group Smoke
     */
    final class SmokeTest extends TestCase
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
        public function testComposerCanLoadLibraryClass(): void
        {
            // AAA
            $this->assertTrue(class_exists(Linter::class));
        }

        /**
         * @test
         *
         * @small
         *
         * @return void
         */
        public function testLinterInstanceIsObject(): void
        {
            // AAA
            $this->assertNotNull($this->linter);
            // AAA
            $this->assertIsObject($this->linter);
        }

        /**
         * @test
         *
         * @small
         *
         * @return void
         */
        public function testCliInclusion(): void
        {
            try {
                $argv = ['--help'];
                require_once addslashes(dirname(__DIR__) . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR) . 'php-sl.php';
            } catch (Throwable) {
                $this->fail();
            }

            $this->assertTrue(true); // Explicit pass.
        }
    }
}
