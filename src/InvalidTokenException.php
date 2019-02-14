<?php
namespace Fernet;

class InvalidTokenException extends \UnexpectedValueException implements Exception
{
    public function __construct($message = "Invalid token", $code = 0, \Throwable $previous = null) {
        parent::__construct($message, $code, $previous);
    }
}
