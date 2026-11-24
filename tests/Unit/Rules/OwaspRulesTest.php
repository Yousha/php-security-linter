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
        $this->rules = OwaspRules::getRules();
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
        // Arrange
        $pattern = null;
        foreach ($this->rules as $rule) {
            if ($rule['id'] === 'OWASP-015') {
                $pattern = $rule['pattern'];
                break;
            }
        }
        $this->assertNotNull($pattern, 'OWASP-015 (Weak Hash) rule not found');

        // Act & Assert
        $this->assertMatchesRegularExpression($pattern, '<?php $hash = hash("md5", $password); ?>');
        $this->assertMatchesRegularExpression($pattern, '<?php $hash = hash("sha1", $data); ?>');
        $this->assertDoesNotMatchRegularExpression($pattern, '<?php $hash = hash("sha256", $password); ?>');
        $this->assertDoesNotMatchRegularExpression($pattern, '<?php $hash = password_hash($password, PASSWORD_DEFAULT); ?>');
    }

    public function testOwaspA08InsecureDeserializationUnserializePattern(): void
    {
        // Arrange
        $pattern = null;
        foreach ($this->rules as $rule) {
            if ($rule['id'] === 'OWASP-016') {
                $pattern = $rule['pattern'];
                break;
            }
        }
        $this->assertNotNull($pattern, 'OWASP-016 (unserialize) rule not found');

        // Act & Assert
        $this->assertMatchesRegularExpression($pattern, '<?php $data = unserialize($_GET["obj"]); ?>');
        $this->assertMatchesRegularExpression($pattern, '<?php $data = unserialize($_POST["data"]); ?>');
        $this->assertDoesNotMatchRegularExpression($pattern, '<?php $data = unserialize($trustedData); ?>');
    }

    public function testOwaspA10SsrFPattern(): void
    {
        // Arrange
        $pattern = null;
        foreach ($this->rules as $rule) {
            if ($rule['id'] === 'OWASP-017') {
                $pattern = $rule['pattern'];
                break;
            }
        }
        $this->assertNotNull($pattern, 'OWASP-017 rule not found');

        // Act & Assert
        $this->assertMatchesRegularExpression($pattern, '<?php $content = file_get_contents($_GET["url"]); ?>');
        $this->assertMatchesRegularExpression($pattern, '<?php $ch = curl_init($_REQUEST["endpoint"]); ?>');
        $this->assertDoesNotMatchRegularExpression($pattern, '<?php $content = file_get_contents("https://api.example.com/data"); ?>');
    }

    public function testOwaspA07ReflectedXssPattern(): void
    {
        // Arrange
        $pattern = null;
        foreach ($this->rules as $rule) {
            if ($rule['id'] === 'OWASP-018') {
                $pattern = $rule['pattern'];
                break;
            }
        }
        $this->assertNotNull($pattern, 'OWASP-018 (Reflected XSS) rule not found');

        // Act & Assert
        $this->assertMatchesRegularExpression($pattern, '<?php echo $_GET["name"]; ?>');
        $this->assertMatchesRegularExpression($pattern, '<?php echo $_POST["comment"]; ?>');
        $this->assertDoesNotMatchRegularExpression($pattern, '<?php echo $safeVariable; ?>');
    }
}
