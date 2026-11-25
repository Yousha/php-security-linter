<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Yousha\PhpSecurityLinter\Linter;
use Yousha\PhpSecurityLinter\Rules\CisRules;
use Yousha\PhpSecurityLinter\Rules\OwaspRules;

final class DetectionAccuracyTest extends TestCase
{
    /** @dataProvider examples */
    public function testFindingsRequireEvidence(string $id, string $positive, string $negative): void
    {
        // Arrange
        $dir = sys_get_temp_dir() . '/php-sl-accuracy-' . bin2hex(random_bytes(8));
        mkdir($dir);
        $hit = $dir . '/positive.php';
        $clean = $dir . '/negative.php';
        $hitKey = str_replace('\\', '/', $hit);
        $cleanKey = str_replace('\\', '/', $clean);
        file_put_contents($hit, "<?php\n\n" . $positive);
        file_put_contents($clean, "<?php\n\n" . $negative);
        try {
            // Act
            $result = (new Linter())->scan($dir);

            // Assert
            self::assertSame(2, $result['_meta']['scanned_count']);
            self::assertArrayNotHasKey('warnings', $result['_meta']);
            self::assertSame(1, $result['_meta']['issue_count']);
            self::assertArrayNotHasKey($cleanKey, $result);
            self::assertStringStartsWith($id . ':', $result[$hitKey][0]['message']);
            self::assertSame(3, $result[$hitKey][0]['line']);
            $references = [
                'OWASP-A1-SQL' => 'A03:2021', 'OWASP-A1-CMD' => 'A03:2021', 'OWASP-A3' => 'A03:2021',
                'OWASP-A2' => 'A02:2021', 'OWASP-A4' => 'A01:2021', 'OWASP-A5' => 'A05:2021',
                'OWASP-A6' => 'A06:2021', 'OWASP-A7' => 'A07:2021', 'OWASP-A10' => 'A10:2021',
                'OWASP-API1' => 'API4:2023',
            ];
            self::assertSame($references[$id] ?? null, $result[$hitKey][0]['standardReference'] ?? null);
        } finally {
            unlink($hit);
            unlink($clean);
            rmdir($dir);
        }
    }

    public static function examples(): array
    {
        return [
            ['CIS-001', "ini_set('disable_functions', 'exec');", "// disable_functions = exec,system,passthru,shell_exec,proc_open,popen"],
            ['CIS-002', "ini_set('display_errors', 'On');", "ini_set('display_errors', 'Off');"],
            ['CIS-003', 'include $base . $_GET["view"];', 'require("../layout/header.php");'],
            ['CIS-004', 'fopen("/tmp/report.txt", "w");', 'tmpfile(); tempnam(sys_get_temp_dir(), "report"); fopen("/tmp/report.txt", "x");'],
            ['CIS-005', 'session_id($_COOKIE["id"]);', "session_start();\nsession_regenerate_id(true);"],
            ['CIS-006', 'md5($password);', 'hash("sha256", $asset); $passwordField = null;'],
            ['CIS-006', "hash('md5', \$password);", "hash('sha256', \$password);"],
            ['CIS-006', 'crypt($password);', 'crypt($password, \'$6$strong-salt$\');'],
            ['CIS-007', 'openssl_encrypt($data, $cipher, "literal-test-key");', '$key = "0123456789abcdef";'],
            ['CIS-008', 'mysqli_query($db, $query . $_POST["field"]);', 'mysqli_query($db, "SELECT 1"); $form = $_POST;'],
            ['CIS-009', 'header( "Location: " . $_GET["next"] );', 'header("Location: /home"); $form = $_GET;'],
            ['CIS-009', 'header("Location: {$_GET[\'next\']}");', 'header("Location: /page/" . $_GET["page"]);'],
            ['CIS-010', 'curl_setopt($client, CURLOPT_SSL_VERIFYPEER, false);', 'curl_setopt($client, CURLOPT_SSL_VERIFYPEER, true); $other = false;'],
            ['OWASP-A1-SQL', '$sql = "SELECT item FROM items WHERE id=" . $_GET["id"];', '$sql = "SELECT 1"; $form = $_GET;'],
            ['OWASP-A1-SQL', '$id = $_GET["id"]; $sql = "SELECT item FROM items WHERE id=" . $id;', '$id = 10; $sql = "SELECT item FROM items WHERE id=" . $id;'],
            ['CIS-008', '$id = $_GET["id"]; $pdo->query("SELECT * FROM items WHERE id=" . $id);', '$id = 10; $pdo->query("SELECT * FROM items WHERE id=" . $id);'],
            ['CIS-008', '$query = "SELECT * FROM items WHERE id=" . $_GET["id"]; pg_query($connection, $query);', '$query = "SELECT 1"; pg_query($connection, $query);'],
            ['CIS-008', 'DB::raw($_GET["sort"]);', 'DB::raw("created_at DESC");'],
            ['CIS-008', 'DB::select("SELECT * FROM items WHERE id=" . $_GET["id"]);', 'DB::select("SELECT 1");'],
            ['CIS-008', '$query->whereRaw($_GET["filter"]);', '$query->whereRaw("status = 1");'],
            ['OWASP-A1-CMD', 'system($_GET["command"]);', '$runner->system($_GET["command"]);'],
            ['OWASP-A1-CMD', '$command = $_GET["command"]; system($command);', '$command = "uptime"; system($command);'],
            ['OWASP-A2', '$password = "test-password";', '$compass = "north";'],
            ['OWASP-A3', 'echo $_POST["name"];', 'echo htmlspecialchars($_POST["name"]);'],
            ['OWASP-A3', '$name = $_GET["name"]; echo $name;', '$name = $_GET["name"]; $safe = htmlspecialchars($name); echo $safe;'],
            ['OWASP-A4', '?><form method="post"></form>', "?><form method='post'>\n<input name='csrf_token' type='hidden'></form><form method='get'></form>"],
            ['OWASP-A4', '?><form method="post"></form>', '?><form method="POST"><?= csrf_field() ?></form>'],
            ['OWASP-A4', '?> <form method="post"><?php echo $dynamicContent; ?></form>', '?> <form method="post"><?php echo csrf_field(); ?></form>'],
            ['OWASP-A4', '?> <form method="post"></form>', '?> <form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="x"></form>'],
            ['OWASP-A5', "define(\n'APP_DEBUG', true);", '// define("APP_DEBUG", true);'],
            ['OWASP-A6', '?><script src="/js/jquery-3.4.1.min.js"></script>', '?><p>Previously used jquery 1.2</p><script src="/jquery-3.5.0.min.js"></script>'],
            ['OWASP-A6', '?><script src="/bootstrap@3.4.0/dist/js/bootstrap.min.js"></script>', '?><script src="/bootstrap@3.4.1/dist/js/bootstrap.min.js"></script>'],
            ['OWASP-A7', '$min_password_length = 6;', '$min_password_length = 60;'],
            ['OWASP-A8', 'error_log($_POST["ssn"]);', 'isset($_POST["ssn"]);'],
            ['OWASP-A10', 'file_get_contents($_GET["source"]);', 'file_get_contents("local.txt"); $form = $_GET;'],
            ['OWASP-A10', '$url = $_GET["url"]; curl_init($url);', '$url = "https://example.test"; curl_init($url);'],
            ['OWASP-A10', '$url = $_GET["url"]; $client->request("GET", $url);', '$url = "https://example.test"; $client->request("GET", $url);'],
            ['OWASP-A10', '$url = $_GET["url"]; curl_setopt($client, CURLOPT_URL, $url);', '$url = "https://example.test"; curl_setopt($client, CURLOPT_URL, $url);'],
            ['OWASP-API1', 'Route::get("/status", $handler)->withoutMiddleware("throttle:api");', 'function api_status() { return 1; }'],
            ['OWASP-API1', '$route->withoutMiddleware(["auth", "throttle:api"]);', '$route->middleware(["auth", "throttle:api"]);'],
            ['OWASP-WEAK-RNG', '$random = mt_rand(); $resetToken = $random;', '$resetToken = bin2hex(random_bytes(32));'],
            ['OWASP-DESERIALIZATION', '$object = unserialize($payload);', '$object = unserialize($payload, ["allowed_classes" => false]);'],
            ['OWASP-CLOUD1', '$aws_key = "AKIA' . str_repeat('TEST', 4) . '";', '$aws_key = "placeholder";'],
            ['OWASP-CLOUD1', '$aws_secret = "' . str_repeat('Test1234', 5) . '";', '$aws_access_key_id = "AKIAIOSFODNN7EXAMPLE";'],
            ['OWASP-A5', 'define("APP_DEBUG", true);', <<<'SRC'
                $example = 'define("APP_DEBUG", true);';
                $notes = <<<'TXT'
                echo $_POST["name"]; tmpfile();
                TXT;
                // define("APP_DEBUG", true);
                ?><p>tmpfile()</p><!-- <form method="post"></form> -->
                SRC
            ],
        ];
    }

    public function testMalformedSourceIsReportedAlongsideFindingsFromOtherFiles(): void
    {
        // Arrange
        $dir = sys_get_temp_dir() . '/php-sl-parse-' . bin2hex(random_bytes(8));
        mkdir($dir);
        file_put_contents($dir . '/broken.php', '<?php function (');
        file_put_contents($dir . '/valid.php', '<?php define("APP_DEBUG", true);');
        try {
            // Act
            $result = (new Linter())->scan($dir);

            // Assert
            self::assertSame(1, $result['_meta']['issue_count']);
            self::assertStringContainsString('broken.php', $result['_meta']['warnings'][0]);
            self::assertArrayHasKey($dir . '/valid.php', $result);
        } finally {
            unlink($dir . '/broken.php');
            unlink($dir . '/valid.php');
            rmdir($dir);
        }
    }

    public function testExamplesCoverEveryRegisteredDetector(): void
    {
        // Arrange
        $registered = array_column(array_merge(CisRules::getRules(), OwaspRules::getRules()), 'id');

        // Act
        $tested = array_values(array_unique(array_column(self::examples(), 0)));
        sort($registered);
        sort($tested);

        // Assert
        self::assertCount(24, $registered);
        self::assertSame($registered, $tested);
    }
}
