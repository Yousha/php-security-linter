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
     * - id: string Unique identifier for the rule
     * - severity: string (critical/high/medium/low)
     * - message: string Description of the vulnerability
     * - pattern: string Regex pattern to detect the issue
     * - reference: string CIS Benchmark reference (optional)
     */
    public static function getRules(): array
    {
        return [
            // PHP Configuration (15 rules)
            [
                'id' => 'CIS-001',
                'severity' => 'critical',
                'message' => 'CIS-001: Dangerous functions not disabled',
                'pattern' => '/disable_functions\s*=\s*[^\n]*(?!(exec|system|passthru|shell_exec|proc_open|popen|eval))/i',
            ],
            [
                'id' => 'CIS-002',
                'severity' => 'high',
                'message' => 'CIS-002: Error reporting exposes stack traces',
                'pattern' => '/display_errors\s*\(\s*true\s*\)/i',
            ],

            // File System (20 rules)
            [
                'id' => 'CIS-003',
                'severity' => 'critical',
                'message' => 'CIS-003: Directory traversal vulnerability',
                'pattern' => '/(include|require)(_once)?\s*\([^)]*\.\.\//i',
            ],
            [
                'id' => 'CIS-004',
                'severity' => 'high',
                'message' => 'CIS-004: Unsafe temporary file creation',
                'pattern' => '/tmpfile\s*\(\)|tempnam\s*\(/i',
            ],

            // Sessions (10 rules)
            [
                'id' => 'CIS-005',
                'severity' => 'high',
                'message' => 'CIS-005: Session fixation possible',
                'pattern' => '/session_start\s*\([^)]*\)\s*;\s*(?!.*session_regenerate_id)/i',
            ],

            // Cryptography (15 rules)
            [
                'id' => 'CIS-006',
                'severity' => 'critical',
                'message' => 'CIS-006: Weak hash function detected',
                'pattern' => '/(md5|sha1)\s*\(.*password/i',
            ],
            [
                'id' => 'CIS-007',
                'severity' => 'high',
                'message' => 'CIS-007: Hardcoded encryption keys',
                'pattern' => '/\$key\s*=\s*[\'"][a-f0-9]{10,}[\'"]/i',
            ],

            // Database (15 rules)
            [
                'id' => 'CIS-008',
                'severity' => 'critical',
                'message' => 'CIS-008: Raw SQL with user input',
                'pattern' => '/mysql(i)?_query\s*\(.*\$_(GET|POST)/i',
            ],

            // Input Validation (15 rules)
            [
                'id' => 'CIS-009',
                'severity' => 'high',
                'message' => 'CIS-009: Unvalidated redirect',
                'pattern' => '/header\s*\(\s*[\'"]Location:\s*\'\.\$_(GET|POST)/i',
            ],

            // Network (10 rules)
            [
                'id' => 'CIS-010',
                'severity' => 'high',
                'message' => 'CIS-010: SSL verification disabled',
                'pattern' => '/curl_setopt\s*\(\s*.*CURLOPT_SSL_VERIFYPEER\s*,\s*false/i',
            ],
            // Dangerous function (extract)
            [
                'id' => 'CIS-011',
                'severity' => 'critical',
                'message' => 'CIS-011: Dangerous use of extract() with user input',
                'pattern' => '/extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)/i',
            ],
            // Dangerous file inclusion
            [
                'id' => 'CIS-012',
                'severity' => 'critical',
                'message' => 'CIS-012: Potential Remote File Inclusion (RFI)',
                'pattern' => '/(include|require|include_once|require_once)\s*\([^)]*\$_(GET|POST|REQUEST)\)/i', // Checks for direct user input in include/require.
            ],

            // Weak randomness
            [
                'id' => 'CIS-013',
                'severity' => 'medium',
                'message' => 'CIS-013: Use of weak random number generator (rand)',
                'pattern' => '/rand\s*\(\s*\)/i',
            ],

            // Exposing sensitive information in error logs (CIS related)
            [
                'id' => 'CIS-014',
                'severity' => 'high',
                'message' => 'CIS-014: Error logging might expose sensitive data',
                'pattern' => '/error_log\s*\([^)]*\$_(GET|POST|COOKIE|SERVER|REQUEST)/i', // Checks for user input in error_log.
            ],
            // A simple check for *not* setting httponly
            [
                'id' => 'CIS-015',
                'severity' => 'medium',
                'message' => 'CIS-015: Session cookie might lack HttpOnly flag',
                'pattern' => '/session_set_cookie_params\s*\([^)]*(?<!HttpOnly)[,)]/i', // Checks if HttpOnly isn't set as an argument (simplistic)
            ],

            // Insecure deserialization
            [
                'id' => 'CIS-016',
                'severity' => 'critical',
                'message' => 'CIS-016: Insecure deserialization using unserialize',
                'pattern' => '/unserialize\s*\(\s*\$_(GET|POST|COOKIE|REQUEST)/i', // Checks for user input in unserialize.
            ],
        ];
    }
}
