<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests\Unit\Rules;

use PHPUnit\Framework\TestCase;
use Yousha\PhpSecurityLinter\Rules\OwaspRules;

final class OwaspRulesTest extends TestCase
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
        $this->rules = OwaspRules::getRules();
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

    public function ruleDataProvider(): array
    {
        $rules = OwaspRules::getRules();
        $data = [];
        foreach ($rules as $rule) {
            // Extract the ID from the message
            $idMatch = [];
            preg_match('/^(OWASP-[A-Z0-9-]+):/', (string) $rule['message'], $idMatch);
            $id = $idMatch[1] ?? 'unknown';
            $data[] = [$rule, $id];
        }

        return $data;
    }

    public function testOwaspA07WeakPasswordHashPattern(): void
    {
        $pattern = null;
        foreach ($this->rules as $rule) {
            if (str_starts_with((string) $rule['message'], 'OWASP-A07:')) {
                $pattern = $rule['pattern'];
                break;
            }
        }

        $this->assertNotNull($pattern, 'OWASP-A07 (Weak Hash) rule not found');

        $vulnerableCode1 = '<?php $hash = hash("md5", $password); ?>';
        $vulnerableCode2 = '<?php $hash = hash("sha1", $data); ?>';
        $vulnerableCode3 = '<?php $hash = hash("md2", $input); ?>';
        $vulnerableCode4 = '<?php $hash = hash("md4", $input); ?>';
        $vulnerableCode5 = '<?php $hash = hash("sha224", $input); ?>';

        $this->assertMatchesRegularExpression($pattern, $vulnerableCode1);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode2);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode3);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode4);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode5);

        $safeCode1 = '<?php $hash = hash("sha256", $password); ?>';
        $safeCode2 = '<?php $hash = hash("sha512", $data); ?>';
        $safeCode3 = '<?php $hash = password_hash($password, PASSWORD_DEFAULT); ?>';

        $this->assertDoesNotMatchRegularExpression($pattern, $safeCode1);
        $this->assertDoesNotMatchRegularExpression($pattern, $safeCode2);
        $this->assertDoesNotMatchRegularExpression($pattern, $safeCode3);
    }

    public function testOwaspA08InsecureDeserializationUnserializePattern(): void
    {
        $pattern = null;
        foreach ($this->rules as $rule) {
            if (str_starts_with((string) $rule['message'], 'OWASP-A08:')) {
                if (str_contains((string) $rule['message'], 'unserialize')) {
                    $pattern = $rule['pattern'];
                    break;
                }
            }
        }

        $this->assertNotNull($pattern, 'OWASP-A08 (unserialize) rule not found');

        $vulnerableCode1 = '<?php $data = unserialize($_GET["obj"]); ?>';
        $vulnerableCode2 = '<?php $data = unserialize($_POST["data"]); ?>';
        $vulnerableCode3 = '<?php $data = unserialize($_REQUEST["input"]); ?>';
        $vulnerableCode4 = '<?php $data = unserialize($_COOKIE["stored"]); ?>';

        $this->assertMatchesRegularExpression($pattern, $vulnerableCode1);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode2);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode3);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode4);

        // Safe code should not match
        $safeCode1 = '<?php $data = unserialize($trustedData); ?>'; // Variable, not $_GET/POST
        $safeCode2 = '<?php $data = unserialize("a:1:{s:5:\"hello\";s:5:\"world\";}"); ?>'; // Hardcoded string

        $this->assertDoesNotMatchRegularExpression($pattern, $safeCode1);
        $this->assertDoesNotMatchRegularExpression($pattern, $safeCode2);
    }

    public function testOwaspA10SsrFPattern(): void
    {
        $pattern = null;
        foreach ($this->rules as $rule) {
            if (str_starts_with((string) $rule['message'], 'OWASP-A10:')) {
                $pattern = $rule['pattern'];
                break;
            }
        }

        $this->assertNotNull($pattern, 'OWASP-A10 rule not found');

        $vulnerableCode1 = '<?php $content = file_get_contents($_GET["url"]); ?>';
        $vulnerableCode2 = '<?php $fp = fopen($_POST["resource"], "r"); ?>';
        $vulnerableCode3 = '<?php $ch = curl_init($_REQUEST["endpoint"]); ?>';
        $vulnerableCode4 = '<?php $fp = fsockopen($_GET["host"], 80); ?>';
        $vulnerableCode5 = '<?php $fp = stream_socket_client("tcp://" . $_POST["address"] . ":80"); ?>';

        $this->assertMatchesRegularExpression($pattern, $vulnerableCode1);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode2);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode3);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode4);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode5);

        // Safe code should not match
        $safeCode1 = '<?php $content = file_get_contents("https://api.example.com/data"); ?>'; // Hardcoded URL
        $safeCode2 = '<?php $fp = fopen($validatedUrl, "r"); ?>'; // Variable, not $_GET/POST

        $this->assertDoesNotMatchRegularExpression($pattern, $safeCode1);
        $this->assertDoesNotMatchRegularExpression($pattern, $safeCode2);
    }

    public function testOwaspA07ReflectedXssPattern(): void
    {
        $pattern = null;
        foreach ($this->rules as $rule) {
            if (str_starts_with((string) $rule['message'], 'OWASP-A07:')) {
                if (str_contains((string) $rule['message'], 'Reflected XSS')) {
                    $pattern = $rule['pattern'];
                    break;
                }
            }
        }

        $this->assertNotNull($pattern, 'OWASP-A07 (Reflected XSS) rule not found');

        $vulnerableCode1 = '<?php echo $_GET["name"]; ?>';
        $vulnerableCode2 = '<?php echo $_POST["comment"]; ?>';
        $vulnerableCode3 = '<?php echo $_REQUEST["input"]; ?>';
        $vulnerableCode4 = '<?php echo $_COOKIE["username"]; ?>';

        $this->assertMatchesRegularExpression($pattern, $vulnerableCode1);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode2);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode3);
        $this->assertMatchesRegularExpression($pattern, $vulnerableCode4);

        // Safe code should not match (or might need more specific pattern)
        $safeCode1 = '<?php echo htmlspecialchars($_GET["name"]); ?>'; // Output is sanitized

        $safeCode2 = '<?php echo $safeVariable; ?>'; // Variable, not $_GET/POST
        $this->assertDoesNotMatchRegularExpression($pattern, $safeCode2);
    }
}
