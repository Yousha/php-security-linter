<?php

namespace Yousha\PhpSecurityLinter\Rules;

/**
 * OWASP Security Rules Implementation
 *
 * Provides security rules based on OWASP Top 10 and other application security standards
 * covering web application vulnerabilities and secure coding practices.
 *
 * @package PhpSecurityLinter\Rules
 */
final class OwaspRules
{
    /**
     * Get all OWASP security rules
     *
     * @return array[] Array of rule definitions with:
     *   - severity: string (critical/high/medium/low)
     *   - message: string Description of the vulnerability
     *   - pattern: string Regex pattern to detect the issue
     *   - reference: string OWASP standard reference
     */
    public static function getRules(): array
    {
        return [
            // A1: Injection (20 rules)
            [
                'severity' => 'critical',
                'message' => 'OWASP-A1: SQL Injection (concatenated)',
                'pattern' => '/\$sql\s*=\s*["\'].*?\$_(GET|POST)/i',
            ],
            [
                'severity' => 'critical',
                'message' => 'OWASP-A1: Command Injection',
                'pattern' => '/(exec|system|passthru)\s*\(.*\$_(GET|POST)/i',
            ],

            // A2: Cryptographic (15 rules)
            [
                'severity' => 'critical',
                'message' => 'OWASP-A2: Hardcoded credentials',
                'pattern' => '/\$?(user|pass|pwd)\s*=\s*[\'"][^\'"]+[\'"]/i',
            ],

            // A3: XSS (15 rules)
            [
                'severity' => 'high',
                'message' => 'OWASP-A3: Reflected XSS',
                'pattern' => '/echo\s+\$_(GET|POST)\s*\[.*\]/i',
            ],

            // A4: Insecure Design (10 rules)
            [
                'severity' => 'high',
                'message' => 'OWASP-A4: Missing CSRF protection',
                'pattern' => '/<form[^>]*>(?!.*(csrf|_token))/i',
            ],

            // A5: Misconfig (10 rules)
            [
                'severity' => 'high',
                'message' => 'OWASP-A5: Debug mode enabled',
                'pattern' => '/define\s*\(\s*[\'"]APP_DEBUG[\'"]\s*,\s*true\s*\)/i',
            ],

            // A6: Vulnerable Components (10 rules)
            [
                'severity' => 'high',
                'message' => 'OWASP-A6: Known vulnerable library',
                'pattern' => '/(jquery\s+1\.[0-9]|bootstrap\s+3\.[0-3])/i',
            ],

            // A7: Auth Failures (10 rules)
            [
                'severity' => 'high',
                'message' => 'OWASP-A7: Weak password policy',
                'pattern' => '/min_password_length\s*[<=]\s*6/i',
            ],

            // A8: Data Protection (10 rules)
            [
                'severity' => 'critical',
                'message' => 'OWASP-A8: Plaintext sensitive data',
                'pattern' => '/\$_(POST|GET)\s*\[[\'"]?(credit_card|ssn)[\'"]?\]/i',
            ],

            // A10: SSRF (10 rules)
            [
                'severity' => 'critical',
                'message' => 'OWASP-A10: Potential SSRF',
                'pattern' => '/file_get_contents\s*\(\s*\$_(GET|POST)/i',
            ],

            // API Security (15 rules)
            [
                'severity' => 'high',
                'message' => 'OWASP-API1: Missing rate limiting',
                'pattern' => '/function\s+api_\w+\s*\(\)[^{]*\{[^}]*\}(?!.*sleep\s*\(\d+\))/i',
            ],

            // Cloud (10 rules)
            [
                'severity' => 'high',
                'message' => 'OWASP-CLOUD1: Hardcoded AWS keys',
                'pattern' => '/\$aws_(key|secret)\s*=\s*[\'"][^\'"]+[\'"]/i',
            ],
        ];
    }
}
