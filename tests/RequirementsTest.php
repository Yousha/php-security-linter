<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests {

    use PHPUnit\Framework\TestCase;

    #[\PHPUnit\Framework\Attributes\Group('Requirements')]
    #[\PHPUnit\Framework\Attributes\Small]
    final class RequirementsTest extends TestCase
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

        /** Verify  project required php version behavior. */
        #[\PHPUnit\Framework\Attributes\Test]
        final public function testProjectRequiredPhpVersion(): void
        {
        // Arrange
$_result = (PHP_MAJOR_VERSION == 8) && (PHP_MINOR_VERSION >= 2);

        // Act

        // Assert
            $this->assertTrue($_result);
        }

        /** Verify  project required php version behavior. */
        #[\PHPUnit\Framework\Attributes\Test]
        final public function testProjectRequiredPhpExtensions(): void
        {
        // Arrange
$extensions = [
                'pcre',
            ];
            foreach ($extensions as $extension) {

        // Act

        // Assert
                $this->assertTrue(extension_loaded($extension));
            }
        }

        /** Verify  project required php version behavior. */
        #[\PHPUnit\Framework\Attributes\Test]
        final public function testProjectDirectoriesExist(): void
        {
        // Arrange
$directories = [
                'bin',
                'resources',
                'src',
                'tests',
                'vendor',
            ];
            foreach ($directories as $directory) {

        // Act

        // Assert
                $this->assertDirectoryExists($directory);
            }
        }

        /** Verify  project required php version behavior. */
        #[\PHPUnit\Framework\Attributes\Test]
        final public function testProjectFilesExist(): void
        {
        // Arrange
$files = [
                '.editorconfig',
                '.gitattributes',
                '.gitignore',
                '.mailmap',
                '.phplint.yml',
                'CHANGELOG.txt',
                'CODE_OF_CONDUCT.txt',
                'composer.json',
                'CONTRIBUTING.txt',
                'CONTRIBUTORS.txt',
                'DCO.txt',
                'FAQ.txt',
                'LICENSE',
                'NOTICE.txt',
                '.php-cs-fixer.php',
                'phpunit.xml',
                'README.md',
                'rector.php',
                'TODO.txt',
                'VERSION.txt',
            ];
            foreach ($files as $file) {

        // Act

        // Assert
                $this->assertFileExists($file);
            }
        }
    }
}
