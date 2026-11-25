<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Rules;

use Closure;
use DOMDocument;
use DOMElement;

final class TemplateInspector
{
    private const DYNAMIC = 'php_sl_dynamic_csrf_fragment';

    public static function inspect(string $source, Closure $report): void
    {
        if (stripos($source, '<form') === false && stripos($source, '<script') === false) {
            return;
        }

        // Keep only PHP fragments that visibly emit or reference a CSRF token.
        // Arbitrary dynamic PHP must not suppress the whole form check.
        $html = '';
        $inPhp = false;
        $phpBuffer = '';
        foreach (token_get_all($source) as $token) {
            if (!is_array($token)) {
                if ($inPhp) {
                    $phpBuffer .= $token;
                } else {
                    $html .= $token;
                }
                continue;
            }
            if ($token[0] === T_INLINE_HTML) {
                $html .= $token[1];
                continue;
            }
            if ($token[0] === T_OPEN_TAG || $token[0] === T_OPEN_TAG_WITH_ECHO) {
                $inPhp = true;
                $phpBuffer = '';
                $html .= str_repeat("\n", substr_count($token[1], "\n"));
                continue;
            }
            if ($token[0] === T_CLOSE_TAG) {
                if (self::containsCsrfMarker($phpBuffer)) {
                    $html .= self::DYNAMIC;
                }
                $html .= str_repeat("\n", substr_count($token[1], "\n"));
                $inPhp = false;
                $phpBuffer = '';
                continue;
            }
            if ($inPhp) {
                $phpBuffer .= $token[1];
            }
            $html .= str_repeat("\n", substr_count($token[1], "\n"));
        }
        if ($inPhp && self::containsCsrfMarker($phpBuffer)) {
            $html .= self::DYNAMIC;
        }

        $dom = new DOMDocument();
        if (!$dom->loadHTML('<html><body>' . $html . '</body></html>', LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING)) {
            return;
        }
        foreach ($dom->getElementsByTagName('form') as $form) {
            if (strcasecmp(trim($form->getAttribute('method')), 'post') !== 0) {
                continue;
            }
            $markup = $dom->saveHTML($form);
            if (strpos($markup, self::DYNAMIC) === false && stripos($markup, '@csrf') === false
                && !self::hasCsrfInput($form)) {
                $report('OWASP-A4', $form->getLineNo());
            }
        }
        foreach ($dom->getElementsByTagName('script') as $script) {
            $path = parse_url($script->getAttribute('src'), PHP_URL_PATH);
            if (is_string($path) && self::outdatedScript($path)) {
                $report('OWASP-A6', $script->getLineNo());
            }
        }
    }

    private static function containsCsrfMarker(string $php): bool
    {
        return DetectionVisitor::matches(
            '~(?:csrf_field|csrf_token|csrfmiddlewaretoken|authenticity_token|requestverificationtoken|_token|xsrf)~i',
            $php
        );
    }

    private static function hasCsrfInput(DOMElement $form): bool
    {
        foreach ($form->getElementsByTagName('input') as $input) {
            $name = strtolower($input->getAttribute('name'));
            if (strcasecmp($input->getAttribute('type'), 'hidden') === 0
                && (strpos($name, 'csrf') !== false
                    || in_array($name, ['_token', 'authenticity_token', 'csrfmiddlewaretoken',
                        '__requestverificationtoken', 'requestverificationtoken', '_csrf_token'], true))) {
                return true;
            }
        }
        return false;
    }

    private static function outdatedScript(string $path): bool
    {
        // Versioned filenames and package paths (e.g. jquery@3.4.1/dist/jquery.min.js).
        $file = basename($path);
        if (!DetectionVisitor::matches('~^(jquery|bootstrap)[.-](\d+\.\d+\.\d+)(?:\.min)?\.js$~iD', $file, $match)) {
            if (!DetectionVisitor::matches('~(?:^|/)(jquery|bootstrap)[@/](\d+\.\d+\.\d+)/(?:[^/]+/)*\1(?:\.min)?\.js$~iD', $path, $match)) {
                return false;
            }
        }
        $version = $match[2];
        if (strtolower($match[1]) === 'jquery') {
            return version_compare($version, '3.5.0', '<');
        }
        return (strpos($version, '3.') === 0 && version_compare($version, '3.4.1', '<'))
            || (strpos($version, '4.') === 0 && version_compare($version, '4.3.1', '<'));
    }
}
