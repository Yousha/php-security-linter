<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Tests\Unit\Reporting;

use PHPUnit\Framework\TestCase;
use Yousha\PhpSecurityLinter\Reporting\SarifFormatter;
use Yousha\PhpSecurityLinter\Rules\CisRules;
use Yousha\PhpSecurityLinter\Rules\OwaspRules;

/**
 * Tests SARIF 2.1.0 report serialization.
 */
#[\PHPUnit\Framework\Attributes\Small]
final class SarifFormatterTest extends TestCase
{
    /**
     * Verify finding metadata and its physical source location.
     */
    public function testFormatsFindingsAsSarif21(): void
    {
        // Arrange
        $formatter = new SarifFormatter();
        $root = sys_get_temp_dir() . '/php-sl-sarif-' . bin2hex(random_bytes(5));
        mkdir($root);
        $file = $root . '/unsafe.php';
        file_put_contents($file, "<?php\nexec(\$_GET['cmd']);\n");

        try {
            // Act
            $json = $formatter->format([
                $file => [[
                    'severity' => 'critical',
                    'message' => 'OWASP-002: OS Command Injection risk (exec/system with unsanitized input)',
                    'line' => 2,
                ]],
                '_meta' => [
                    'scanned_count' => 1,
                    'issue_count' => 1,
                    'warning_count' => 0,
                    'warnings' => [],
                ],
            ], $root);
            $document = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

            // Assert
            self::assertSame('2.1.0', $document['version']);
            self::assertCount(1, $document['runs']);
            self::assertSame('PHP Security Linter', $document['runs'][0]['tool']['driver']['name']);
            self::assertSame('OWASP-002', $document['runs'][0]['results'][0]['ruleId']);
            self::assertSame('error', $document['runs'][0]['results'][0]['level']);
            self::assertSame(
                'unsafe.php',
                $document['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']
            );
            self::assertSame(
                2,
                $document['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']['startLine']
            );
            self::assertSame('A03:2021', $document['runs'][0]['results'][0]['properties']['standardReference']);
            self::assertSame(
                'https://owasp.org/Top10/A03_2021/',
                array_column($document['runs'][0]['tool']['driver']['rules'], null, 'id')['OWASP-002']['helpUri']
            );
            self::assertTrue($document['runs'][0]['invocations'][0]['executionSuccessful']);
        } finally {
            unlink($file);
            rmdir($root);
        }
    }

    /**
     * Verify a scan with no findings produces an empty result set.
     */
    public function testFormatsCleanScanWithoutFindings(): void
    {
        // Arrange
        $formatter = new SarifFormatter();

        // Act
        $document = json_decode($formatter->format([
            '_meta' => [
                'scanned_count' => 0,
                'issue_count' => 0,
                'warning_count' => 0,
                'warnings' => [],
            ],
        ], sys_get_temp_dir()), true, 512, JSON_THROW_ON_ERROR);

        // Assert
        self::assertSame([], $document['runs'][0]['results']);
        self::assertTrue($document['runs'][0]['invocations'][0]['executionSuccessful']);
    }

    /**
     * Verify scan warnings are execution notifications, not vulnerability results.
     */
    public function testFormatsScanWarningsAsExecutionNotifications(): void
    {
        // Arrange
        $formatter = new SarifFormatter();

        // Act
        $document = json_decode($formatter->format([
            '_meta' => [
                'scanned_count' => 0,
                'issue_count' => 0,
                'warning_count' => 1,
                'warnings' => ['Could not read file: unreadable.php'],
            ],
        ], sys_get_temp_dir()), true, 512, JSON_THROW_ON_ERROR);

        // Assert
        self::assertSame([], $document['runs'][0]['results']);
        self::assertFalse($document['runs'][0]['invocations'][0]['executionSuccessful']);
        self::assertSame(
            'Could not read file: unreadable.php',
            $document['runs'][0]['invocations'][0]['toolExecutionNotifications'][0]['message']['text']
        );
    }

    /**
     * Verify every registered rule is declared once and result indexes match descriptors.
     */
    public function testIncludesAllRegisteredRulesWithStableIndexes(): void
    {
        // Arrange
        $registeredRules = array_merge(CisRules::getRules(), OwaspRules::getRules());
        $formatter = new SarifFormatter();

        // Act
        $document = json_decode($formatter->format([
            '_meta' => ['warnings' => []],
        ], sys_get_temp_dir()), true, 512, JSON_THROW_ON_ERROR);
        $descriptors = $document['runs'][0]['tool']['driver']['rules'];
        $descriptorIds = array_column($descriptors, 'id');

        // Assert
        self::assertCount(count($registeredRules), $descriptors);
        self::assertCount(count(array_unique($descriptorIds)), $descriptorIds);

        foreach ($registeredRules as $index => $rule) {
            self::assertSame($rule['id'], $descriptors[$index]['id']);
        }
    }

    /**
     * Verify legacy OWASP message prefixes still resolve to their registered rule IDs.
     */
    public function testResolvesOwaspRulesWhoseMessagePrefixDiffersFromRuleId(): void
    {
        // Arrange
        $formatter = new SarifFormatter();
        $rule = $this->getRuleById('OWASP-013');

        // Act
        $document = json_decode($formatter->format([
            __FILE__ => [[
                'severity' => $rule['severity'],
                'message' => $rule['message'],
                'line' => 1,
            ]],
            '_meta' => ['warnings' => []],
        ], dirname(__DIR__, 3)), true, 512, JSON_THROW_ON_ERROR);

        // Assert
        self::assertCount(1, $document['runs'][0]['results']);
        self::assertSame('OWASP-013', $document['runs'][0]['results'][0]['ruleId']);
        self::assertSame('error', $document['runs'][0]['results'][0]['level']);
        self::assertArrayNotHasKey('properties', $document['runs'][0]['results'][0]);
    }

    /**
     * Verify all supported scanner severities map to valid SARIF levels.
     */
    public function testMapsScannerSeveritiesToSarifLevels(): void
    {
        // Arrange
        $formatter = new SarifFormatter();
        $cases = [
            ['OWASP-002', 'error'],
            ['OWASP-005', 'error'],
            ['OWASP-008', 'warning'],
            ['OWASP-010', 'note'],
        ];
        $findings = [];

        foreach ($cases as [$ruleId, $expectedLevel]) {
            $rule = $this->getRuleById($ruleId);
            $findings[] = [
                'severity' => $rule['severity'],
                'message' => $rule['message'],
                'line' => 3,
            ];
        }

        // Act
        $document = json_decode($formatter->format([
            __FILE__ => $findings,
            '_meta' => ['warnings' => []],
        ], dirname(__DIR__, 3)), true, 512, JSON_THROW_ON_ERROR);
        $results = $document['runs'][0]['results'];

        // Assert
        self::assertCount(count($cases), $results);
        foreach ($cases as $index => [$ruleId, $expectedLevel]) {
            self::assertSame($ruleId, $results[$index]['ruleId']);
            self::assertSame($expectedLevel, $results[$index]['level']);
            self::assertSame(
                $results[$index]['ruleId'],
                $document['runs'][0]['tool']['driver']['rules'][$results[$index]['ruleIndex']]['id']
            );
        }
    }

    /**
     * Verify artifact URI encoding and invalid line numbers are normalized.
     */
    public function testEncodesArtifactUriAndNormalizesLineNumber(): void
    {
        // Arrange
        $formatter = new SarifFormatter();
        $root = sys_get_temp_dir() . '/php-sl-sarif-uri-' . bin2hex(random_bytes(5));
        mkdir($root);
        $file = $root . '/source file #1.php';
        file_put_contents($file, "<?php echo \$_GET['value'];");

        try {
            $rule = $this->getRuleById('OWASP-007');

            // Act
            $document = json_decode($formatter->format([
                $file => [[
                    'severity' => $rule['severity'],
                    'message' => $rule['message'],
                    'line' => -5,
                ]],
                '_meta' => ['warnings' => []],
            ], $root), true, 512, JSON_THROW_ON_ERROR);
            $result = $document['runs'][0]['results'][0];

            // Assert
            self::assertSame(
                'source%20file%20%231.php',
                $result['locations'][0]['physicalLocation']['artifactLocation']['uri']
            );
            self::assertSame(1, $result['locations'][0]['physicalLocation']['region']['startLine']);
        } finally {
            unlink($file);
            rmdir($root);
        }
    }

    /**
     * Verify unrecognized findings are not emitted as fabricated SARIF results.
     */
    public function testSkipsFindingsThatDoNotMatchRegisteredRules(): void
    {
        // Arrange
        $formatter = new SarifFormatter();

        // Act
        $document = json_decode($formatter->format([
            __FILE__ => [[
                'severity' => 'high',
                'message' => 'UNKNOWN-999: Unregistered finding',
                'line' => 9,
            ]],
            '_meta' => ['warnings' => []],
        ], dirname(__DIR__, 3)), true, 512, JSON_THROW_ON_ERROR);

        // Assert
        self::assertSame([], $document['runs'][0]['results']);
    }

    /**
     * Find a registered rule by its stable identifier.
     *
     * @return array<string, mixed>
     */
    private function getRuleById(string $ruleId): array
    {
        foreach (array_merge(CisRules::getRules(), OwaspRules::getRules()) as $rule) {
            if ($rule['id'] === $ruleId) {
                return $rule;
            }
        }

        self::fail(sprintf('Rule %s was not registered.', $ruleId));
    }

}
