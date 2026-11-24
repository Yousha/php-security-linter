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

        /** Verify  composer can load library class behavior. */
        #[\PHPUnit\Framework\Attributes\Test]
        public function testComposerCanLoadLibraryClass(): void
        {
        // Arrange

        // Act

        // Assert
            $this->assertTrue(class_exists(Linter::class));
        }

        /** Verify  composer can load library class behavior. */
        #[\PHPUnit\Framework\Attributes\Test]
        public function testLinterInstanceIsObject(): void
        {
        // Arrange

        // Act

        // Assert
            $this->assertNotNull($this->linter);
            $this->assertIsObject($this->linter);
        }
    }
}
