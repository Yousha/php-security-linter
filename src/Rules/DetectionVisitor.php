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
    private array $taintedVariables = [];
    private array $htmlSafeVariables = [];

    public function __construct(Closure $report)
    {
        $this->report = $report;
    }

    public function enterNode(Node $node)
    {
        $id = null;
        if ($node instanceof Expr\Assign && $node->var instanceof Expr\Variable && is_string($node->var->name)) {
            $id = $this->assignment(strtolower($node->var->name), $node->expr);
        } elseif ($node instanceof Expr\FuncCall && $node->name instanceof Name) {
            $id = $this->inspectCall(strtolower($node->name->toString()), $node);
        } elseif ($node instanceof Expr\Include_ && $this->isTainted($node->expr)) {
            $id = 'CIS-003';
        } elseif ($node instanceof Stmt\Echo_ || $node instanceof Expr\Print_) {
            foreach ($node instanceof Stmt\Echo_ ? $node->exprs : [$node->expr] as $expr) {
                if ($this->hasUnsafeOutput($expr)) {
                    $id = 'OWASP-A3';
                }
            }
        } elseif ($node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall) {
            $id = $this->inspectMethodCall($node);
        } elseif ($node instanceof Expr\ShellExec && $this->isTainted($node->shell)) {
            $id = 'OWASP-A1-CMD';
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

    /** Determine whether an expression contains request-controlled data or a variable derived from it. */
    private function isTainted(?Node $node): bool
    {
        if ($node instanceof Expr\Variable && is_string($node->name)) {
            return in_array($node->name, ['_GET', '_POST', '_REQUEST', '_COOKIE'], true)
                || isset($this->taintedVariables[$node->name]);
        }
        if ($node instanceof Expr\ArrayDimFetch) {
            return $this->isTainted($node->var);
        }
        if ($node instanceof Expr\BinaryOp) {
            return $this->isTainted($node->left) || $this->isTainted($node->right);
        }
        if ($node instanceof Scalar\Encapsed) {
            foreach ($node->parts as $part) {
                if ($this->isTainted($part)) {
                    return true;
                }
            }
        }
        if ($node instanceof Expr\FuncCall || $node instanceof Expr\MethodCall || $node instanceof Expr\StaticCall) {
            foreach ($node->args as $arg) {
                if ($this->isTainted($arg->value)) {
                    return true;
                }
            }
        }
        if ($node instanceof Expr\Ternary) {
            return $this->isTainted($node->cond) || $this->isTainted($node->if) || $this->isTainted($node->else);
        }
        if ($node instanceof Expr\Cast) {
            return $this->isTainted($node->expr);
        }
        return false;
    }

    /** Detect tainted values that reach output without an HTML-escaping operation. */
    private function hasUnsafeOutput(?Node $node): bool
    {
        if ($node instanceof Expr\FuncCall && $node->name instanceof Name
            && in_array(strtolower($node->name->toString()), ['htmlspecialchars', 'htmlentities'], true)) {
            return false;
        }
        if ($node instanceof Expr\Variable && is_string($node->name)) {
            return $this->isTainted($node) && !isset($this->htmlSafeVariables[$node->name]);
        }
        if ($node instanceof Expr\ArrayDimFetch) {
            return $this->hasUnsafeOutput($node->var);
        }
        if ($node instanceof Expr\BinaryOp) {
            return $this->hasUnsafeOutput($node->left) || $this->hasUnsafeOutput($node->right);
        }
        if ($node instanceof Scalar\Encapsed) {
            foreach ($node->parts as $part) {
                if ($this->hasUnsafeOutput($part)) {
                    return true;
                }
            }
        }
        if ($node instanceof Expr\Ternary) {
            return $this->hasUnsafeOutput($node->if) || $this->hasUnsafeOutput($node->else);
        }
        return false;
    }

    private static function prefix(?Node $expr): string
    {
        while ($expr instanceof Expr\BinaryOp\Concat) {
            $expr = $expr->left;
        }
        if ($expr instanceof Scalar\Encapsed && isset($expr->parts[0]) && $expr->parts[0] instanceof Scalar\EncapsedStringPart) {
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
                return $this->isTainted($first) ? 'CIS-005' : null;
            case 'md5':
            case 'sha1':
                return 'CIS-006';
            case 'hash':
                return in_array(strtolower(self::literal($first) ?? ''), ['md5', 'sha1'], true) ? 'CIS-006' : null;
            case 'crypt':
                $salt = self::literal($second);
                return $second === null || $salt === '' || ($salt !== null && strpos($salt, '$') !== 0 && strlen($salt) <= 2)
                    ? 'CIS-006' : null;
            case 'openssl_encrypt':
            case 'openssl_decrypt':
                return self::literal($third) !== null && self::literal($third) !== '' ? 'CIS-007' : null;
            case 'mysql_query':
                return $this->isTainted($first) ? 'CIS-008' : null;
            case 'mysqli_query':
                return $this->isTainted($second) ? 'CIS-008' : null;
            case 'pg_query':
            case 'pg_send_query':
                return $this->isTainted($second) || $this->isTainted($first) ? 'CIS-008' : null;
            case 'pg_prepare':
                return $this->isTainted($third) ? 'CIS-008' : null;
            case 'header':
                return self::matches('/^location:\s*(?:(?:https?:)?\/\/)?$/iD', self::prefix($first)) && $this->isTainted($first) ? 'CIS-009' : null;
            case 'curl_setopt':
                if ($second instanceof Expr\ConstFetch && strtoupper($second->name->toString()) === 'CURLOPT_URL' && $this->isTainted($third)) {
                    return 'OWASP-A10';
                }
                return $second instanceof Expr\ConstFetch && strtoupper($second->name->toString()) === 'CURLOPT_SSL_VERIFYPEER'
                    && self::boolean($third) === false ? 'CIS-010' : null;
            case 'curl_setopt_array':
                return $this->curlUrlOptionIsTainted($second) ? 'OWASP-A10' : null;
            case 'exec':
            case 'shell_exec':
            case 'system':
            case 'passthru':
            case 'proc_open':
            case 'popen':
                return $this->isTainted($first) ? 'OWASP-A1-CMD' : null;
            case 'define':
                return $value === 'APP_DEBUG' && self::boolean($second) === true ? 'OWASP-A5' : null;
            case 'error_log':
            case 'file_put_contents':
                return $this->isTainted($name === 'error_log' ? $first : $second) ? 'OWASP-A8' : null;
            case 'file_get_contents':
                return $this->isTainted($first) && in_array(strtolower(self::prefix($first)), ['', 'http://', 'https://'], true) ? 'OWASP-A10' : null;
            case 'curl_init':
                return $this->isTainted($first) ? 'OWASP-A10' : null;
            case 'unserialize':
                return $this->allowsNoClasses($second) ? null : 'OWASP-DESERIALIZATION';
            case 'rand':
            case 'mt_rand':
            case 'lcg_value':
            case 'uniqid':
                return null;
        }
        return null;
    }

    private function inspectMethodCall(Expr\MethodCall $node): ?string
    {
        $method = $node->name instanceof Node\Identifier ? strtolower($node->name->name) : '';
        $first = $node->args[0]->value ?? null;

        if ($method === 'withoutmiddleware' && $this->removesThrottle($node)) {
            return 'OWASP-API1';
        }
        if (in_array($method, ['query', 'exec', 'prepare'], true) && $this->isTainted($first)) {
            return 'CIS-008';
        }
        if (in_array($method, ['request', 'get', 'post', 'put', 'patch', 'delete', 'send'], true)
            && ($this->isTainted($first) || ($method === 'request' && $this->isTainted($node->args[1]->value ?? null)))) {
            return 'OWASP-A10';
        }
        if ($method === 'setoption' && ($node->args[0]->value ?? null) instanceof Expr\ConstFetch
            && strtoupper($node->args[0]->value->name->toString()) === 'CURLOPT_URL' && $this->isTainted($node->args[1]->value ?? null)) {
            return 'OWASP-A10';
        }
        return null;
    }

    private function curlUrlOptionIsTainted(?Node $options): bool
    {
        if (!$options instanceof Expr\Array_) {
            return false;
        }
        foreach ($options->items as $item) {
            if ($item === null || !$item->key instanceof Expr\ConstFetch) {
                continue;
            }
            if (strtoupper($item->key->name->toString()) === 'CURLOPT_URL' && $this->isTainted($item->value)) {
                return true;
            }
        }
        return false;
    }

    private function allowsNoClasses(?Node $options): bool
    {
        if (!$options instanceof Expr\Array_) {
            return false;
        }
        foreach ($options->items as $item) {
            if ($item !== null && self::literal($item->key) === 'allowed_classes' && self::boolean($item->value) === false) {
                return true;
            }
        }
        return false;
    }

    private function assignment(string $name, Expr $expr): ?string
    {
        $tainted = $this->isTainted($expr);
        $htmlSafe = $expr instanceof Expr\FuncCall && $expr->name instanceof Name
            && in_array(strtolower($expr->name->toString()), ['htmlspecialchars', 'htmlentities'], true);

        if ($tainted) {
            $this->taintedVariables[$name] = true;
        } else {
            unset($this->taintedVariables[$name]);
        }
        if ($htmlSafe) {
            $this->htmlSafeVariables[$name] = true;
        } else {
            unset($this->htmlSafeVariables[$name]);
        }

        if ($name === 'sql' && $tainted
            && self::matches('/^\s*(?:SELECT|INSERT|UPDATE|DELETE|REPLACE|WITH)\b/i', self::prefix($expr))) {
            return 'OWASP-A1-SQL';
        }
        if ($name === 'min_password_length' && $expr instanceof Scalar\LNumber && $expr->value <= 6) {
            return 'OWASP-A7';
        }
        if (in_array($name, ['pass', 'password', 'passwd', 'pwd'], true) && self::literal($expr) !== null && self::literal($expr) !== '') {
            return 'OWASP-A2';
        }
        if (in_array($name, ['encryptionkey', 'encryption_key'], true)) {
            return 'CIS-007';
        }
        if ($this->containsWeakRandom($expr) && self::matches('/(?:token|nonce|session|csrf|secret|key|otp|reset)/i', $name)) {
            return 'OWASP-WEAK-RNG';
        }
        $value = self::literal($expr);
        if ($value === null || $value === '' || strpos(strtoupper($value), 'EXAMPLE') !== false || strlen(count_chars($value, 3)) < 4) {
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

    private function containsWeakRandom(Node $node): bool
    {
        if ($node instanceof Expr\FuncCall && $node->name instanceof Name
            && in_array(strtolower($node->name->toString()), ['rand', 'mt_rand', 'lcg_value', 'uniqid'], true)) {
            return true;
        }
        foreach ($node->getSubNodeNames() as $subNodeName) {
            $child = $node->$subNodeName;
            if ($child instanceof Node && $this->containsWeakRandom($child)) {
                return true;
            }
            if (is_array($child)) {
                foreach ($child as $item) {
                    if ($item instanceof Node && $this->containsWeakRandom($item)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private function removesThrottle(Expr\MethodCall $node): bool
    {
        if (!$node->name instanceof Node\Identifier || strtolower($node->name->name) !== 'withoutmiddleware') {
            return false;
        }
        $arg = $node->args[0]->value ?? null;
        $values = $arg instanceof Expr\Array_ ? array_map(static function ($item) {
            return $item !== null ? $item->value : null;
        }, $arg->items) : [$arg];
        foreach ($values as $value) {
            $alias = self::literal($value) ?? '';
            if (strpos(strtolower($alias), 'throttle') !== false || ($value instanceof Expr\ClassConstFetch
                && $value->class instanceof Name && $value->class->getLast() === 'ThrottleRequests'
                && $value->name instanceof Node\Identifier && strtolower($value->name->name) === 'class')) {
                return true;
            }
        }
        return false;
    }
}
