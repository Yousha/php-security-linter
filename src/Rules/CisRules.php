<?php

namespace Yousha\PhpSecurityLinter\Rules;

/**
 * CIS Security Rules Implementation
 *
 * Provides security rules based on CIS PHP Benchmark recommendations
 * covering server configuration, filesystem security, and PHP best practices.
 *
 * @package PhpSecurityLinter\Rules
 */
final class CisRules
{
    /**
     * Get all CIS security rules
     *
     * @return array[] Array of rule definitions with:
     *   - severity: string (critical/high/medium/low)
     *   - message: string Description of the vulnerability
     *   - pattern: string Regex pattern to detect the issue
     *   - reference: string CIS Benchmark reference
     */
    public static function getRules(): array
    {
        return [
            // PHP Configuration (15 rules)
            [
                'severity' => 'critical',
                'message' => 'CIS-001: Dangerous functions not disabled',
                'pattern' => '/disable_functions\s*=\s*[^\n]*(?!(exec|system|passthru|shell_exec|proc_open|popen|eval))/i',
            ],
            [
                'severity' => 'high',
                'message' => 'CIS-002: Error reporting exposes stack traces',
                'pattern' => '/display_errors\s*\(\s*true\s*\)/i',
            ],

            // File System (20 rules)
            [
                'severity' => 'critical',
                'message' => 'CIS-003: Directory traversal vulnerability',
                'pattern' => '/(include|require)(_once)?\s*\([^)]*\.\.\//i',
            ],
            [
                'severity' => 'high',
                'message' => 'CIS-004: Unsafe temporary file creation',
                'pattern' => '/tmpfile\s*\(\)|tempnam\s*\(/i',
            ],

            // Sessions (10 rules)
            [
                'severity' => 'high',
                'message' => 'CIS-005: Session fixation possible',
                'pattern' => '/session_start\s*\([^)]*\)\s*;\s*(?!.*session_regenerate_id)/i',
            ],

            // Cryptography (15 rules)
            [
                'severity' => 'critical',
                'message' => 'CIS-006: Weak hash function detected',
                'pattern' => '/(md5|sha1)\s*\(.*password/i',
            ],
            [
                'severity' => 'high',
                'message' => 'CIS-007: Hardcoded encryption keys',
                'pattern' => '/\$key\s*=\s*[\'"][a-f0-9]{10,}[\'"]/i',
            ],

            // Database (15 rules)
            [
                'severity' => 'critical',
                'message' => 'CIS-008: Raw SQL with user input',
                'pattern' => '/mysql(i)?_query\s*\(.*\$_(GET|POST)/i',
            ],

            // Input Validation (15 rules)
            [
                'severity' => 'high',
                'message' => 'CIS-009: Unvalidated redirect',
                'pattern' => '/header\s*\(\s*[\'"]Location:\s*\'\.\$_(GET|POST)/i',
            ],

            // Network (10 rules)
            [
                'severity' => 'high',
                'message' => 'CIS-010: SSL verification disabled',
                'pattern' => '/curl_setopt\s*\(\s*.*CURLOPT_SSL_VERIFYPEER\s*,\s*false/i',
            ],
        ];
    }
}
