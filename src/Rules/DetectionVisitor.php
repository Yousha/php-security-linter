<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Rules;

use Closure;
use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar;
use PhpParser\Node\Stmt;
use PhpParser\NodeVisitorAbstract;

final class DetectionVisitor extends NodeVisitorAbstract
{
    private Closure $report;

    public function __construct(Closure $report)
    {
        $this->report = $report;
    }

    public function enterNode(Node $node)
    {
        $id = null;
        if ($node instanceof Expr\FuncCall && $node->name instanceof Name) {
            $id = $this->inspectCall(strtolower($node->name->toString()), $node);
        } elseif ($node instanceof Expr\Assign && $node->var instanceof Expr\Variable && is_string($node->var->name)) {
            $id = $this->assignment(strtolower($node->var->name), $node->expr);
        } elseif ($node instanceof Expr\Include_ && self::inputInText($node->expr)) {
            $id = 'CIS-003';
        } elseif ($node instanceof Stmt\Echo_ || $node instanceof Expr\Print_) {
            foreach ($node instanceof Stmt\Echo_ ? $node->exprs : [$node->expr] as $expr) {
                if (self::inputInText($expr)) {
                    $id = 'OWASP-A3';
                }
            }
        } elseif ($node instanceof Expr\MethodCall && $this->removesThrottle($node)) {
            $id = 'OWASP-API1';
        }
        if ($id !== null) {
            ($this->report)($id, $node->getStartLine());
        }
        return null;
    }

    private static function literal(?Node $node): ?string
    {
        return $node instanceof Scalar\String_ ? $node->value : null;
    }

    private static function boolean(?Node $node): ?bool
    {
        if ($node instanceof Expr\ConstFetch) {
            $name = strtolower($node->name->toString());
            return ['true' => true, 'false' => false][$name] ?? null;
        }
        if ($node instanceof Scalar\LNumber || $node instanceof Scalar\String_) {
            $values = ['1' => true, 'on' => true, 'yes' => true, 'true' => true, 'stderr' => true,
                '0' => false, 'off' => false, 'no' => false, 'false' => false, '' => false];
            return $values[strtolower((string) $node->value)] ?? null;
        }
        return null;
    }

    /** Follow raw request values through concatenation and interpolation only. */
    private static function inputInText(?Node $node, ?array $fields = null): bool
    {
        if ($node instanceof Expr\BinaryOp\Concat) {
            return self::inputInText($node->left, $fields) || self::inputInText($node->right, $fields);
        }
        if ($node instanceof Scalar\Encapsed) {
            foreach ($node->parts as $part) {
                if (self::inputInText($part, $fields)) {
                    return true;
                }
            }
        }
        $field = null;
        while ($node instanceof Expr\ArrayDimFetch) {
            $field = self::literal($node->dim);
            $node = $node->var;
        }
        return $node instanceof Expr\Variable && in_array($node->name, ['_GET', '_POST', '_REQUEST', '_COOKIE'], true)
            && ($fields === null || in_array($field, $fields, true));
    }

    private static function prefix(?Node $expr): string
    {
        while ($expr instanceof Expr\BinaryOp\Concat) {
            $expr = $expr->left;
        }
        if ($expr instanceof Scalar\Encapsed && $expr->parts[0] instanceof Scalar\EncapsedStringPart) {
            return $expr->parts[0]->value;
        }
        return self::literal($expr) ?? '';
    }

    /** Preserve the scanner's incomplete-scan warning when PCRE cannot evaluate a check. */
    public static function matches(string $pattern, string $value, ?array &$groups = null): bool
    {
        $result = preg_match($pattern, $value, $groups);
        if ($result === false) {
            throw new \RuntimeException('PCRE error ' . preg_last_error());
        }
        return $result === 1;
    }

    private function inspectCall(string $name, Expr\FuncCall $node): ?string
    {
        $first = $node->args[0]->value ?? null;
        $second = $node->args[1]->value ?? null;
        $third = $node->args[2]->value ?? null;
        $value = self::literal($first);
        switch ($name) {
            case 'ini_set':
            case 'ini_alter':
                if ($value === 'disable_functions') {
                    return 'CIS-001';
                }
                return $value === 'display_errors' && self::boolean($second) === true ? 'CIS-002' : null;
            case 'fopen':
                return $value !== null && strpos($value, '/tmp/') === 0 && self::matches('/^[wac]/', self::literal($second) ?? '') ? 'CIS-004' : null;
            case 'session_id':
                return self::inputInText($first) ? 'CIS-005' : null;
            case 'md5':
            case 'sha1':
                $field = $first instanceof Expr\ArrayDimFetch ? self::literal($first->dim) : null;
                $var = $first instanceof Expr\Variable && is_string($first->name) ? $first->name : $field;
                return in_array(strtolower($var ?? ''), ['password', 'passwd', 'pass', 'pwd'], true) ? 'CIS-006' : null;
            case 'openssl_encrypt':
            case 'openssl_decrypt':
                return self::literal($third) !== null && self::literal($third) !== '' ? 'CIS-007' : null;
            case 'mysql_query':
            case 'mysqli_query':
                return self::inputInText($name === 'mysqli_query' ? $second : $first) ? 'CIS-008' : null;
            case 'header':
                return self::matches('/^location:\s*(?:(?:https?:)?\/\/)?$/iD', self::prefix($first)) && self::inputInText($first) ? 'CIS-009' : null;
            case 'curl_setopt':
                return $second instanceof Expr\ConstFetch && $second->name->toString() === 'CURLOPT_SSL_VERIFYPEER'
                    && self::boolean($third) === false ? 'CIS-010' : null;
            case 'exec':
            case 'shell_exec':
            case 'system':
            case 'passthru':
                return self::inputInText($first) ? 'OWASP-A1-CMD' : null;
            case 'define':
                return $value === 'APP_DEBUG' && self::boolean($second) === true ? 'OWASP-A5' : null;
            case 'error_log':
            case 'file_put_contents':
                return self::inputInText($name === 'error_log' ? $first : $second, ['credit_card', 'ssn']) ? 'OWASP-A8' : null;
            case 'file_get_contents':
                return self::inputInText($first) && in_array(strtolower(self::prefix($first)), ['', 'http://', 'https://'], true) ? 'OWASP-A10' : null;
        }
        return null;
    }

    private function assignment(string $name, Expr $expr): ?string
    {
        if ($name === 'sql' && self::inputInText($expr)
            && self::matches('/^\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|WITH)\b/i', self::prefix($expr))) {
            return 'OWASP-A1-SQL';
        }
        if ($name === 'min_password_length' && $expr instanceof Scalar\LNumber && $expr->value <= 6) {
            return 'OWASP-A7';
        }
        $value = self::literal($expr);
        if ($value === null || $value === '') {
            return null;
        }
        if (in_array($name, ['pass', 'password', 'passwd', 'pwd'], true)) {
            return 'OWASP-A2';
        }
        if (in_array($name, ['encryptionkey', 'encryption_key'], true)) {
            return 'CIS-007';
        }
        if (strpos(strtoupper($value), 'EXAMPLE') !== false || strlen(count_chars($value, 3)) < 4) {
            return null;
        }
        if (in_array($name, ['aws_key', 'aws_access_key_id'], true) && self::matches('/^(?:AKIA|ASIA)[A-Z0-9]{16}$/D', $value)) {
            return 'OWASP-CLOUD1';
        }
        if (in_array($name, ['aws_secret', 'aws_secret_access_key'], true) && self::matches('~^[A-Za-z0-9/+=]{40}$~D', $value)) {
            return 'OWASP-CLOUD1';
        }
        return null;
    }

    private function removesThrottle(Expr\MethodCall $node): bool
    {
        if (!$node->name instanceof Node\Identifier || strtolower($node->name->name) !== 'withoutmiddleware') {
            return false;
        }
        $base = $node->var;
        while ($base instanceof Expr\MethodCall) {
            $base = $base->var;
        }
        if (!$base instanceof Expr\StaticCall || !$base->class instanceof Name || strtolower($base->class->getLast()) !== 'route') {
            return false;
        }
        $arg = $node->args[0]->value ?? null;
        $values = $arg instanceof Expr\Array_ ? array_map(static function ($item) {
            return $item->value ?? null;
        }, $arg->items) : [$arg];
        foreach ($values as $value) {
            $alias = self::literal($value) ?? '';
            if (explode(':', $alias, 2)[0] === 'throttle' || ($value instanceof Expr\ClassConstFetch
                && $value->class instanceof Name && $value->class->getLast() === 'ThrottleRequests'
                && $value->name instanceof Node\Identifier && strtolower($value->name->name) === 'class')) {
                return true;
            }
        }
        return false;
    }
}
