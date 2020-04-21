<?php

namespace fssy\jwt\exception;

class TokenExpiredException extends TokenException
{
    protected $message = 'token expired';
    protected $code = -1002;
}
