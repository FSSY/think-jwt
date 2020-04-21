<?php

namespace fssy\jwt\exception;

class TokenIsNotValidException extends TokenException
{
    protected $message = 'token is not valid';
    protected $code = -1003;
}
