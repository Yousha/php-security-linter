<?php

declare(strict_types=1);

namespace Yousha\PhpSecurityLinter\Exceptions;

use Throwable;

/** Represents errors raised while scanning PHP files. */
final class LinterException extends \RuntimeException
{
    /** Create a linter exception with optional diagnostic context. */
    public function __construct(
        string $message = "",
        int $code = 0,
        ?Throwable $previous = null,
        protected ?string $context = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    /** Return additional diagnostic context, if available. */
    public function getContext(): ?string
    {
        return $this->context;
    }

    /** Create an exception for an inaccessible file. */
    public static function fileAccessError(string $filePath): self
    {
        return new self(
            sprintf('Could not access file: %s', $filePath),
            100,
            null,
            'Check file permissions and existence'
        );
    }

    /** Create an exception for a file parsing failure. */
    public static function parsingError(string $filePath, string $error): self
    {
        return new self(
            sprintf('Error parsing file %s: %s', $filePath, $error),
            200,
            null,
            'Check file syntax and encoding'
        );
    }

    /** Create an exception for an invalid security rule. */
    public static function invalidRule(string $rule): self
    {
        return new self(
            sprintf('Invalid security rule: %s', $rule),
            300,
            null,
            'Check rule configuration and pattern validity'
        );
    }

    /** Return the exception message, context, and stack trace. */
    public function __toString(): string
    {
        $str = self::class . sprintf(': [%s]: %s%s', $this->code, $this->message, PHP_EOL);

        if ($this->context) {
            $str .= sprintf('Context: %s%s', $this->context, PHP_EOL);
        }

        $str .= "Stack trace:\n" . $this->getTraceAsString();
        return $str;
    }
}
