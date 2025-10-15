<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use Yousha\PhpSecurityLinter\Rules\CisRules;

final class CisRulesTest extends TestCase
{
    private array $rules;

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
        $this->rules = CisRules::getRules();
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
     * Test that the rules array is correctly structured and not empty.
     */
    public function testRulesArrayStructure(): void
    {
        $this->assertIsArray($this->rules);
        $this->assertNotEmpty($this->rules);

        foreach ($this->rules as $rule) {
            $this->assertArrayHasKey('id', $rule);
            $this->assertIsString($rule['id']);
            $this->assertStringStartsWith('CIS-', $rule['id']);

            $this->assertArrayHasKey('severity', $rule);
            $this->assertIsString($rule['severity']);

            $this->assertArrayHasKey('message', $rule);
            $this->assertIsString($rule['message']);

            $this->assertArrayHasKey('pattern', $rule);
            $this->assertIsString($rule['pattern']);
        }
    }

    /**
     * Data provider for vulnerable and clean code snippets for each CIS rule.
     * * The array structure is: [rule_id, vulnerable_code, clean_code]
     */
    public static function ruleDataProvider(): array
    {
        return [
            // CIS-001: Direct call to dangerous function detected
            ['CIS-001', '<?php eval($code); system("ls");', '<?php if (true) { /* no exec */ }'],

            // CIS-002: Error reporting exposes stack traces
            ['CIS-002', '<?php display_errors(true);', '<?php ini_set("display_errors", "Off");'],

            // CIS-003: Directory traversal vulnerability
            ['CIS-003', '<?php include(__DIR__ . "/../../config.php");', '<?php require_once("config.php");'],

            // CIS-004: Unsafe temporary file creation
            ['CIS-004', '<?php $tmp = tempnam("/tmp", "prefix");', '<?php $safe = sys_get_temp_dir();'],

            // CIS-005: Session fixation possible
            ['CIS-005', '<?php session_start(); $_SESSION["user"] = 1;', '<?php session_start(); session_regenerate_id(true);'],

            // CIS-006: Weak hash function detected
            ['CIS-006', '<?php $hash = md5($password);', '<?php $hash = password_hash($password, PASSWORD_DEFAULT);'],

            // CIS-007: Hardcoded encryption keys
            ['CIS-007', '<?php $key = "a1b2c3d4e5f6g7h8i9j0";', '<?php $key = $_ENV["SECRET_KEY"];'],

            // CIS-008: Raw SQL with user input
            ['CIS-008', '<?php mysqli_query($db, "SELECT * FROM users WHERE id=" . $_GET["id"]);', '<?php $stmt->execute([$id]);'],

            // CIS-009: Unvalidated redirect
            ['CIS-009', '<?php header("Location: " . $_POST["url"]);', '<?php header("Location: /dashboard");'],

            // CIS-011: Dangerous use of extract() with user input
            ['CIS-011', '<?php extract($_REQUEST);', '<?php extract($data, EXTR_SKIP);'],

            // CIS-010: SSL verification disabled
            ['CIS-010', '<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);', '<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);'],
        ];
    }
}
