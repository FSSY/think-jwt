<?php

namespace fssy\jwt\exception;

use Exception;
use Throwable;

class TokenException extends Exception
{
    protected $message = 'token exception';
    protected $code = -1000;

    public function __construct($message = "", $code = 0, Throwable $previous = null)
    {
        parent::__construct($message ?: $this->getMessage(), $code ?: $this->getCode(), $previous);
    }
}
