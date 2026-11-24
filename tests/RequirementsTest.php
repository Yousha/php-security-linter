<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests {

    use PHPUnit\Framework\TestCase;

    /**
     * @group Requirements
     * @small
     */
    final class RequirementsTest extends TestCase
    {
        /**
         * This method is called before the first test method in the test class is executed.
         *
         *
         * @return void
         */
        public static function setUpBeforeClass(): void {}

        /**
         * This method is called after the last test method in the test class has been executed.
         *
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
         *
         * @return void
         */
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
        final public function testProjectRequiredPhpVersion(): void
        {
            $this->assertGreaterThanOrEqual(80000, PHP_VERSION_ID);
        }

        /**
         *
         *
         * @return void
         */
        final public function testProjectRequiredPhpExtensions(): void
        {
            $extensions = [
                'pcre',
                'tokenizer',
            ];

            foreach ($extensions as $extension) {
                $this->assertTrue(extension_loaded($extension));
            }
        }

        /**
         *
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
         *
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
                'rector.php',
                'TODO.txt',
                'VERSION.txt',
            ];

            foreach ($files as $file) {
                $this->assertFileExists($file);
            }
        }
    }
}
