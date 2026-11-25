<?php

namespace Yousha\PhpSecurityLinter\Rules;

/** Project rule IDs are stable. Optional references identify the mapped OWASP edition and category. */
final class OwaspRules
{
    /** Return metadata for the branch's built-in detectors. */
    public static function getRules(): array
    {
        return [
            ['id' => 'OWASP-A1-SQL', 'standardReference' => 'A03:2021', 'severity' => 'critical', 'message' => 'OWASP-A1-SQL: Request input concatenated into SQL text'],
            ['id' => 'OWASP-A1-CMD', 'standardReference' => 'A03:2021', 'severity' => 'critical', 'message' => 'OWASP-A1-CMD: Request input used in a shell command'],
            ['id' => 'OWASP-A2', 'standardReference' => 'A02:2021', 'severity' => 'high', 'message' => 'OWASP-A2: Password variable assigned a literal credential'],
            ['id' => 'OWASP-A3', 'standardReference' => 'A03:2021', 'severity' => 'high', 'message' => 'OWASP-A3: Request input directly included in output'],
            ['id' => 'OWASP-A4', 'standardReference' => 'A01:2021', 'severity' => 'medium', 'message' => 'OWASP-A4: POST form has no recognizable hidden CSRF field; verify server-side protection'],
            ['id' => 'OWASP-A5', 'standardReference' => 'A05:2021', 'severity' => 'high', 'message' => 'OWASP-A5: Debug mode explicitly enabled'],
            ['id' => 'OWASP-A6', 'standardReference' => 'A06:2021', 'severity' => 'high', 'message' => 'OWASP-A6: Script references a library version predating a security fix'],
            ['id' => 'OWASP-A7', 'standardReference' => 'A07:2021', 'severity' => 'high', 'message' => 'OWASP-A7: Configured minimum password length is six or less'],
            ['id' => 'OWASP-A8', 'severity' => 'high', 'message' => 'OWASP-A8: Sensitive request field written directly to a file or log'],
            ['id' => 'OWASP-A10', 'standardReference' => 'A10:2021', 'severity' => 'critical', 'message' => 'OWASP-A10: Request-controlled data used as a remote resource location'],
            ['id' => 'OWASP-WEAK-RNG', 'severity' => 'high', 'message' => 'OWASP-WEAK-RNG: Predictable random value used for a security-sensitive token or secret'],
            ['id' => 'OWASP-DESERIALIZATION', 'severity' => 'high', 'message' => 'OWASP-DESERIALIZATION: Unrestricted PHP object deserialization'],
            ['id' => 'OWASP-API1', 'standardReference' => 'API4:2023', 'severity' => 'medium', 'message' => 'OWASP-API1: Route explicitly removes throttle middleware; verify alternative rate limits'],
            ['id' => 'OWASP-CLOUD1', 'severity' => 'high', 'message' => 'OWASP-CLOUD1: AWS credential variable assigned a key-shaped literal'],
        ];
    }
}
