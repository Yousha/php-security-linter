<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Rules;

final class RuleCatalog
{
    public static function all(bool $includeAttack = true): array
    {
        return array_merge(CisRules::getRules(), OwaspRules::getRules(), $includeAttack ? AttackRules::getRules() : []);
    }
}
