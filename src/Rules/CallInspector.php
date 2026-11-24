<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Rules;

use PhpToken;

/** Inspect direct calls and literal arguments without executing the scanned source. */
final class CallInspector
{
    private const DIRECTIVES = [
        'session.use_strict_mode' => [false, 'OWASP-020'],
        'session.use_trans_sid' => [true, 'OWASP-021'],
        'session.use_only_cookies' => [false, 'OWASP-022'],
        'display_startup_errors' => [true, 'OWASP-026'],
        'html_errors' => [true, 'OWASP-027'],
        'zend.exception_ignore_args' => [false, 'OWASP-028'],
    ];

    public static function findings(string $source, array $activeRules): array
    {
        $tokens = array_values(array_filter(
            PhpToken::tokenize($source),
            static fn(PhpToken $token): bool => !$token->isIgnorable()
        ));
        $findings = [];
        foreach ($tokens as $index => $token) {
            if (!$token->is([T_STRING, T_NAME_FULLY_QUALIFIED, T_EVAL])) {
                continue;
            }
            $previous = $tokens[$index - 1] ?? null;
            if ($previous && $previous->is([T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_NEW, T_FUNCTION])) {
                continue;
            }
            $name = strtolower(ltrim($token->text, '\\'));
            if (!in_array($name, ['ini_set', 'ini_alter', 'setcookie', 'setrawcookie', 'session_set_cookie_params', 'password_hash', 'eval', 'file_put_contents', 'copy'], true)
                || ($tokens[$index + 1]->text ?? null) !== '(') {
                continue;
            }
            $args = self::arguments($tokens, $index + 1);
            foreach (self::matchCall($name, $args) as $id) {
                if (isset($activeRules[$id])) {
                    $rule = $activeRules[$id];
                    $findings[] = ['severity' => $rule['severity'], 'message' => $rule['message'], 'line' => $token->line];
                }
            }
        }
        return $findings;
    }

    /** Split a parenthesized argument list or array on top-level commas. */
    private static function arguments(array $tokens, int $opening, ?int &$closing = null): array
    {
        $args = [];
        $part = [];
        $depth = 0;
        for ($i = $opening + 1, $count = count($tokens); $i < $count; $i++) {
            $token = $tokens[$i];
            if ($token->is([')', ']', '}']) && $depth === 0) {
                $closing = $i;
                if ($part !== []) {
                    $args[] = $part;
                }
                return $args;
            }
            if ($token->is(',') && $depth === 0) {
                $args[] = $part;
                $part = [];
                continue;
            }
            if ($token->is(['(', '[', '{', T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES])) {
                $depth++;
            } elseif ($token->is([')', ']', '}'])) {
                $depth--;
            }
            $part[] = $token;
        }
        return [];
    }

    /** Accept simple quoted literals only. Dynamic expressions stay unknown. */
    private static function literal(array $tokens): ?string
    {
        if (count($tokens) !== 1 || !$tokens[0]->is(T_CONSTANT_ENCAPSED_STRING)) {
            return null;
        }
        return substr($tokens[0]->text, 1, -1);
    }

    private static function options(array $tokens): array
    {
        if (($tokens[0]->text ?? '') === '[' && end($tokens)->text === ']') {
            $opening = 0;
        } elseif (isset($tokens[1]) && $tokens[0]->is(T_ARRAY) && $tokens[1]->text === '(' && end($tokens)->text === ')') {
            $opening = 1;
        } else {
            return [];
        }
        $options = [];
        $entries = self::arguments($tokens, $opening, $closing);
        if ($closing !== count($tokens) - 1) {
            return [];
        }
        foreach ($entries as $entry) {
            if (!isset($entry[2]) || !$entry[0]->is(T_CONSTANT_ENCAPSED_STRING) || !$entry[1]->is(T_DOUBLE_ARROW)) {
                return [];
            }
            $options[substr($entry[0]->text, 1, -1)] = array_slice($entry, 2);
        }
        return $options;
    }

    private static function matchCall(string $name, array $args): array
    {
        $first = self::literal($args[0] ?? []);
        $second = $args[1] ?? [];
        if ($name === 'ini_set' || $name === 'ini_alter') {
            $setting = self::DIRECTIVES[$first] ?? null;
            if (!$setting || count($second) !== 1) {
                return [];
            }
            $literal = self::literal($second);
            if ($literal === null && !in_array(strtolower($second[0]->text), ['true', 'false', '0', '1'], true)) {
                return [];
            }
            $value = strtolower($literal ?? $second[0]->text);
            $values = $setting[0] ? ['1', 'on', 'true', 'yes'] : ['', '0', 'off', 'false', 'no'];
            return in_array($value, $values, true) ? [$setting[1]] : [];
        }
        if ($name === 'setcookie' || $name === 'setrawcookie') {
            $options = isset($args[3])
                ? ['path' => $args[3], 'domain' => $args[4] ?? []]
                : self::options($args[2] ?? []);
            return self::cookieRules($first, $options);
        }
        if ($name === 'session_set_cookie_params') {
            return self::cookieRules(null, self::options($args[0] ?? []));
        }
        if ($name === 'password_hash') {
            $options = self::options($args[2] ?? []);
            $cost = $options['cost'] ?? [];
            if (count($second) === 1 && ltrim($second[0]->text, '\\') === 'PASSWORD_BCRYPT'
                && count($cost) === 1 && $cost[0]->is(T_LNUMBER)
                && in_array(intval(str_replace('_', '', $cost[0]->text), 0), range(4, 9), true)) {
                return ['OWASP-029'];
            }
            return [];
        }
        if ($name === 'eval') {
            $data = self::nestedLiteral($args[0] ?? [], 'base64_decode');
            return $data !== null && $data !== '' ? ['ATTACK-001'] : [];
        }
        $destination = $name === 'copy' ? self::literal($second) : $first;
        $url = $name === 'copy' ? $first : self::nestedLiteral($second, 'file_get_contents');
        if ($url !== null && preg_match('~^https?://~i', $url) && preg_match('~\.(?:php|phtml|phar|sh|ps1|bat|cmd)$~iD', $destination ?? '')) {
            return ['ATTACK-002'];
        }
        if ($name === 'file_put_contents' && preg_match('~^/(?:etc/(?:crontab|cron\.d/[^/]+)|var/spool/cron/(?:crontabs/)?[^/]+)$~D', $destination ?? '')) {
            $schedule = self::literal($second);
            if ($schedule !== null && preg_match('/^\s*(?:@(?:reboot|hourly|daily|weekly|monthly|yearly|annually)|(?:[\d*,\/\-]+[ \t]+){4}[\d*,\/\-]+)[ \t]+\S+/m', $schedule)) {
                return ['ATTACK-003'];
            }
        }
        return [];
    }

    private static function nestedLiteral(array $tokens, string $function): ?string
    {
        if (count($tokens) !== 4 || strtolower(ltrim($tokens[0]->text, '\\')) !== $function
            || $tokens[1]->text !== '(' || $tokens[3]->text !== ')') {
            return null;
        }
        return self::literal([$tokens[2]]);
    }

    private static function cookieRules(?string $name, array $options): array
    {
        $ids = [];
        $secure = $options['secure'] ?? [];
        if (strcasecmp(self::literal($options['samesite'] ?? []) ?? '', 'None') === 0
            && count($secure) === 1 && in_array(strtolower($secure[0]->text), ['false', '0'], true)) {
            $ids[] = 'OWASP-023';
        }
        if (str_starts_with($name ?? '', '__Host-')) {
            $domain = self::literal($options['domain'] ?? []);
            if ($domain !== null && $domain !== '') {
                $ids[] = 'OWASP-024';
            }
            $path = self::literal($options['path'] ?? []);
            if ($path !== null && $path !== '/') {
                $ids[] = 'OWASP-025';
            }
        }
        return $ids;
    }
}
