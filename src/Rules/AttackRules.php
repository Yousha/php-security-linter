<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Rules;

final class AttackRules
{
    public static function getRules(): array
    {
        return [
            [
                'id' => 'ATTACK-001',
                'severity' => 'high',
                'message' => 'ATTACK-001: Review execution of directly Base64-decoded literal content',
                'reference' => 'T1140',
                'helpUri' => 'https://attack.mitre.org/techniques/T1140/',
            ],
            [
                'id' => 'ATTACK-002',
                'severity' => 'medium',
                'message' => 'ATTACK-002: Review remote content copied directly to a script file',
                'reference' => 'T1105',
                'helpUri' => 'https://attack.mitre.org/techniques/T1105/',
            ],
            [
                'id' => 'ATTACK-003',
                'severity' => 'medium',
                'message' => 'ATTACK-003: Review literal schedule written to a cron configuration file',
                'reference' => 'T1053.003',
                'helpUri' => 'https://attack.mitre.org/techniques/T1053/003/',
            ],
        ];
    }
}
