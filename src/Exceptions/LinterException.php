<?php

declare(strict_types=1);

/**
 * LinterException - Custom exception class for PHP Security Linter.
 *
 * @package PhpSecurityLinter
 * @subpackage Exceptions
 */

namespace Yousha\PhpSecurityLinter\Exceptions;

use Throwable;

/**
 * Custom exception class for linter-related errors.
 *
 * This exception is thrown when errors occur during file scanning operations,
 * including file access issues, parsing errors, and other scanning-related problems.
 */
final class LinterException extends \RuntimeException
{
    /**
     * @var string Additional context abouterror.
     */
    protected $context;

    /**
     * LinterException constructor
     *
     * @param string $message The exception message
     * @param int $code The exception code
     * @param Throwable|null $previous Previous exception if nested
     * @param string|null $context Additional context abouterror
     */
    public function __construct(
        string $message = "",
        int $code = 0,
        ?Throwable $previous = null,
        ?string $context = null
    ) {
        parent::__construct($message, $code, $previous);
        $this->context = $context;
    }

    /**
     * Get additional context abouterror.
     *
     * @return string|null
     */
    public function getContext(): ?string
    {
        return $this->context;
    }

    /**
     * Create an exception for file access errors.
     *
     * @param string $filePath Path tofile that couldn't be accessed
     * @return self
     */
    public static function fileAccessError(string $filePath): self
    {
        return new self(
            sprintf('Could not access file: %s', $filePath),
            100,
            null,
            'Check file permissions and existence'
        );
    }

    /**
     * Create an exception for parsing errors.
     *
     * @param string $filePath Path tofile with parsing issues
     * @param string $error Details ofparsing error
     * @return self
     */
    public static function parsingError(string $filePath, string $error): self
    {
        return new self(
            sprintf('Error parsing file %s: %s', $filePath, $error),
            200,
            null,
            'Check file syntax and encoding'
        );
    }

    /**
     * Create an exception for invalid rules.
     *
     * @param string $rule The rule that causederror
     * @return self
     */
    public static function invalidRule(string $rule): self
    {
        return new self(
            sprintf('Invalid security rule: %s', $rule),
            300,
            null,
            'Check rule configuration and pattern validity'
        );
    }

    /**
     * String representation ofexception.
     *
     * @return string
     */
    public function __toString(): string
    {
        $str = __CLASS__ . ": [{$this->code}]: {$this->message}\n";

        if ($this->context) {
            $str .= "Context: {$this->context}\n";
        }

        $str .= "Stack trace:\n" . $this->getTraceAsString();
        return $str;
    }
}
