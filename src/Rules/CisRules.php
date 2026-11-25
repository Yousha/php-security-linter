<?php

namespace Yousha\PhpSecurityLinter\Rules;

/** Local PHP hardening heuristics with project-assigned CIS-prefixed IDs and severities. */
final class CisRules
{
    /** Return metadata for the branch's built-in detectors. */
    public static function getRules(): array
    {
        return [
            ['id' => 'CIS-001', 'severity' => 'medium', 'message' => 'CIS-001: Attempt to change startup-only disable_functions at runtime'],
            ['id' => 'CIS-002', 'severity' => 'high', 'message' => 'CIS-002: PHP error display explicitly enabled'],
            ['id' => 'CIS-003', 'severity' => 'critical', 'message' => 'CIS-003: Request input used in an include path'],
            ['id' => 'CIS-004', 'severity' => 'medium', 'message' => 'CIS-004: Fixed temporary path opened for nonexclusive writing'],
            ['id' => 'CIS-005', 'severity' => 'high', 'message' => 'CIS-005: Session ID explicitly taken from request input'],
            ['id' => 'CIS-006', 'severity' => 'critical', 'message' => 'CIS-006: Fast legacy hash function used; review whether the value is security-sensitive'],
            ['id' => 'CIS-007', 'severity' => 'high', 'message' => 'CIS-007: Literal encryption key in application code'],
            ['id' => 'CIS-008', 'severity' => 'critical', 'message' => 'CIS-008: Request input used in SQL query text'],
            ['id' => 'CIS-009', 'severity' => 'high', 'message' => 'CIS-009: Location header takes its destination from request input'],
            ['id' => 'CIS-010', 'severity' => 'high', 'message' => 'CIS-010: TLS peer verification explicitly disabled'],
        ];
    }
}
