<?php

namespace fssy\jwt\exception;

class TokenDoesNotExistException extends TokenException
{
    protected $message = 'token does not exist';
    protected $code = -1001;
}
