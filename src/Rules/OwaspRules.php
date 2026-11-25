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
    /** Return metadata for the branch's built-in detectors. */
    public static function getRules(): array
    {
        return [
            ['id' => 'OWASP-A1-SQL', 'severity' => 'critical', 'message' => 'OWASP-A1-SQL: Request input concatenated into SQL text'],
            ['id' => 'OWASP-A1-CMD', 'severity' => 'critical', 'message' => 'OWASP-A1-CMD: Request input used in a shell command'],
            ['id' => 'OWASP-A2', 'severity' => 'high', 'message' => 'OWASP-A2: Password variable assigned a literal credential'],
            ['id' => 'OWASP-A3', 'severity' => 'high', 'message' => 'OWASP-A3: Request input directly included in output'],
            ['id' => 'OWASP-A4', 'severity' => 'medium', 'message' => 'OWASP-A4: POST form has no recognizable hidden CSRF field; verify server-side protection'],
            ['id' => 'OWASP-A5', 'severity' => 'high', 'message' => 'OWASP-A5: Debug mode explicitly enabled'],
            ['id' => 'OWASP-A6', 'severity' => 'high', 'message' => 'OWASP-A6: Script references a library version predating a security fix'],
            ['id' => 'OWASP-A7', 'severity' => 'high', 'message' => 'OWASP-A7: Configured minimum password length is six or less'],
            ['id' => 'OWASP-A8', 'severity' => 'high', 'message' => 'OWASP-A8: Sensitive request field written directly to a file or log'],
            ['id' => 'OWASP-A10', 'severity' => 'critical', 'message' => 'OWASP-A10: Request input used as a remote resource location'],
            ['id' => 'OWASP-API1', 'severity' => 'medium', 'message' => 'OWASP-API1: Route explicitly removes throttle middleware; verify alternative rate limits'],
            ['id' => 'OWASP-CLOUD1', 'severity' => 'high', 'message' => 'OWASP-CLOUD1: AWS credential variable assigned a key-shaped literal'],
        ];
    }
}
