<?php


namespace fssy\jwt\exception;

class TokenDoesNotMatchTheSceneException extends TokenException
{
    protected $message = 'token does not match the scene';
    protected $code = -1004;
}
