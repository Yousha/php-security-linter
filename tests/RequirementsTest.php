<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests {

    use PHPUnit\Framework\TestCase;

    /**
     * @group Requirements
     */
    final class RequirementsTest extends TestCase
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
         * @small
         *
         * @return void
         */
        final public function testProjectRequiredPhpVersion(): void
        {
            $_result = (PHP_MAJOR_VERSION == 7) && (PHP_MINOR_VERSION >= 4);
            $this->assertTrue($_result);
        }

        /**
         * @test
         *
         * @small
         *
         * @return void
         */
        final public function testProjectRequiredPhpExtensions(): void
        {
            $extensions = [
                'pcre',
            ];

            foreach ($extensions as $extension) {
                $this->assertTrue(extension_loaded($extension));
            }
        }

        /**
         * @test
         *
         * @small
         *
         * @return void
         */
        final public function testProjectDirectoriesExist(): void
        {
            $directories = [
                'bin',
                'resources',
                'src',
                'tests',
                'vendor',
            ];

            foreach ($directories as $directory) {
                $this->assertDirectoryExists($directory);
            }
        }

        /**
         * @test
         *
         * @small
         *
         * @return void
         */
        final public function testProjectFilesExist(): void
        {
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
                'TODO.txt',
                'VERSION.txt',
            ];

            foreach ($files as $file) {
                $this->assertFileExists($file);
            }
        }
    }
}
