<?php

namespace Yousha\PhpSecurityLinter\Rules;

/**
 * OWASP Top 10 Security Rules Implementation
 *
 * Provides security rules based on the OWASP Top 10 (2021) list,
 * focusing on common, high-impact web application vulnerabilities in PHP.
 *
 * @package PhpSecurityLinter\Rules
 */
final class OwaspRules
{
    /**
     * Get all OWASP Top 10 security rules
     *
     * @return array[] Array of rule definitions with:
     * - id: string Unique identifier for the rule (e.g., OWASP-001)
     * - severity: string (critical/high/medium/low)
     * - message: string Description of the vulnerability
     * - pattern: string Regex pattern to detect the issue
     * - reference: string OWASP A-Code reference (optional)
     */
    public static function getRules(): array
    {
        return [
            // A03:2021 - Injection (SQL, Command, etc.)
            [
                'id' => 'OWASP-001',
                'severity' => 'critical',
                'message' => 'OWASP-001: SQL Injection risk (unsanitized input in query)',
                'pattern' => '/(PDO|mysqli)->query\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)/i',
                'reference' => 'A03:2021',
            ],
            // A03:2021 - Injection (Command)
            [
                'id' => 'OWASP-002',
                'severity' => 'critical',
                'message' => 'OWASP-002: OS Command Injection risk (exec/system with unsanitized input)',
                'pattern' => '/(exec|shell_exec|passthru|system)\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)/i',
                'reference' => 'A03:2021',
            ],
            // A04:2021 - Insecure Design / PHP Object Injection
            [
                'id' => 'OWASP-003',
                'severity' => 'critical',
                'message' => 'OWASP-003: PHP Object Injection risk (unserialize on user input)',
                'pattern' => '/unserialize\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)/i',
                'reference' => 'A04:2021',
            ],
            // A07:2021 - Identification and Authentication Failures
            [
                'id' => 'OWASP-004',
                'severity' => 'critical',
                'message' => 'OWASP-004: Weak password hashing or storing sensitive data in session',
                // FIXED: All capture groups are now correctly closed.
                'pattern' => '/(hash\s*\([^,]*,\s*password\))|(\$_(SESSION)\s*\[.*(password|key|secret)\])/i',
                'reference' => 'A07:2021',
            ],
            // A01:2021 - Broken Access Control
            [
                'id' => 'OWASP-005',
                'severity' => 'high',
                'message' => 'OWASP-005: File inclusion risk (potential Local File Inclusion)',
                'pattern' => '/(include|require)(_once)?\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)/i',
                'reference' => 'A01:2021',
            ],
            // A10:2021 - Server-Side Request Forgery (SSRF)
            [
                'id' => 'OWASP-006',
                'severity' => 'high',
                'message' => 'OWASP-006: Server-Side Request Forgery (SSRF) risk',
                'pattern' => '/(file_get_contents|curl_exec|fsockopen|guzzle|httpclient)\s*\([^)]*(\$_GET|\$_POST|\$_REQUEST)/i',
                'reference' => 'A10:2021',
            ],
            // A07:2021 - XSS (Cross-Site Scripting)
            [
                'id' => 'OWASP-007',
                'severity' => 'high',
                'message' => 'OWASP-007: Cross-Site Scripting (XSS) risk (unescaped output)',
                'pattern' => '/echo\s*(\$_GET|\$_POST|\$_REQUEST)/i',
                'reference' => 'A07:2021',
            ],
            // A02:2021 - Cryptographic Failures
            [
                'id' => 'OWASP-008',
                'severity' => 'medium',
                'message' => 'OWASP-008: Use of weak random number generator',
                'pattern' => '/(rand|mt_rand)\s*\(/i',
                'reference' => 'A02:2021',
            ],
            // A05:2021 - Security Misconfiguration (File Upload)
            [
                'id' => 'OWASP-009',
                'severity' => 'medium',
                'message' => 'OWASP-009: Insecure file upload handling (missing validation)',
                'pattern' => '/move_uploaded_file\s*\([^)]*\)\s*;\s*(?!.*is_uploaded_file)/i',
                'reference' => 'A05:2021',
            ],
            // A05:2021 - Security Misconfiguration (Global Variables)
            [
                'id' => 'OWASP-010',
                'severity' => 'low',
                'message' => 'OWASP-010: Accessing raw superglobals directly (security best practice)',
                'pattern' => '/(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|eval)/i',
                'reference' => 'A05:2021',
            ],
            // A08:2021 - Software and Data Integrity Failures (CSRF is a related issue)
            [
                'id' => 'OWASP-011',
                'severity' => 'high',
                'message' => 'OWASP-011: Missing Cross-Site Request Forgery (CSRF) protection',
                // Checks for a <form method="post"> tag that doesn't contain a hidden input for a token
                'pattern' => '/<form\s+[^>]*method=["\']post["\'][^>]*>(?![^<]*<input[^>]*type=["\']hidden["\'][^>]*name=["\']csrf_token)/i',
                'reference' => 'A08:2021',
            ],
            // A05:2021 - Security Misconfiguration (Cookies)
            [
                'id' => 'OWASP-012',
                'severity' => 'medium',
                'message' => 'OWASP-012: Insecure cookie flags (missing HttpOnly or Secure)',
                // Checks for setcookie() without 'httponly' or 'secure' flags set in the last parameter array or arguments
                'pattern' => '/setcookie\s*\([^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*[^)]*,\s*(?!.*(true|secure|httponly))/i',
                'reference' => 'A05:2021',
            ],
            // A01:2021 - Path Traversal
            [
                'id' => 'OWASP-013',
                'severity' => 'critical',
                'message' => 'OWASP-A01: Path Traversal (Local File Inclusion)',
                'pattern' => '/(include|require|file_get_contents|fopen|readfile)\s*\([^)]*["\']?\s*\.\s*\$_(GET|POST|REQUEST)\s*\.\s*["\']?\)/i', // Looks for direct user input concatenated into file operations.
            ],

            // A06:2021 - Improper Asset Management - Debug files
            [
                'id' => 'OWASP-014',
                'severity' => 'medium',
                'message' => 'OWASP-A06: Potential debug file exposed',
                'pattern' => '/\.(log|sql|bak|backup|old|tmp)$/i', // Checks for common debug file extensions.
            ],
            // A07:2021 - Identification and Authentication Failures - Weak Password Hashing
            [
                'id' => 'OWASP-015',
                'severity' => 'critical',
                'message' => 'OWASP-A07: Weak password hashing algorithm used',
                'pattern' => '/hash\s*\(\s*[\'"](?i)(md2|md4|md5|sha1|sha224)[\'"]/i', // Checks for weak hash functions in hash().
            ],

            // A08:2021 - Software and Data Integrity Failures - Unserialize
            [
                'id' => 'OWASP-016',
                'severity' => 'critical',
                'message' => 'OWASP-A08: Insecure deserialization (unserialize)',
                'pattern' => '/unserialize\s*\(\s*\$_(GET|POST|COOKIE|REQUEST)/i', // Checks for user input in unserialize (same as CIS-017).
            ],

            // A10:2021 - Server-Side Request Forgery
            [
                'id' => 'OWASP-017',
                'severity' => 'critical',
                'message' => 'OWASP-A10: Potential Server-Side Request Forgery (SSRF)',
                'pattern' => '/(file_get_contents|fopen|curl_init|fsockopen|stream_socket_client)\s*\([^)]*\$_(GET|POST|REQUEST)/i', // Checks for user input in various HTTP/file functions.
            ],

            // Cross-Site Scripting (XSS) - Reflected
            [
                'id' => 'OWASP-018',
                'severity' => 'high',
                'message' => 'OWASP-A07: Potential Reflected XSS (outputting user input)',
                'pattern' => '/echo\s+\$_(GET|POST|REQUEST|COOKIE)/i', // Checks for direct output of user input.
            ],

            // A08:2021 - Insecure Deserialization - Alternative pattern
            [
                'id' => 'OWASP-019',
                'severity' => 'critical',
                'message' => 'OWASP-A08: Potential Insecure Deserialization (serialize/unserialize mismatch)',
                'pattern' => '/serialize\s*\(\s*\$_(GET|POST|REQUEST)/i', // Checks for serializing user input (less common than unserialize).
            ],
        ];
    }
}
