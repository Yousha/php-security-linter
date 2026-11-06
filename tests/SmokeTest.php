<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests {

    use Throwable;
    use PHPUnit\Framework\TestCase;
    use Yousha\PhpSecurityLinter\Linter;

    #[\PHPUnit\Framework\Attributes\Group('Smoke')]
    #[\PHPUnit\Framework\Attributes\Small]
    final class SmokeTest extends TestCase
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
        public function testComposerCanLoadLibraryClass(): void
        {
            // AAA
            $this->assertTrue(class_exists(Linter::class));
        }

        /**
         *
         *
         * @return void
         */
        #[\PHPUnit\Framework\Attributes\Test]
        public function testLinterInstanceIsObject(): void
        {
            // AAA
            $this->assertNotNull($this->linter);
            // AAA
            $this->assertIsObject($this->linter);
        }
    }
}
