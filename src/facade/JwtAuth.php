<?php

namespace fssy\jwt\facade;

use think\Facade;

/**
 * Class JwtAuth
 * @see \fssy\jwt\JwtAuth
 * @package fssy\JwtAuth\facade
 * @mixin \fssy\jwt\JwtAuth
 */
class JwtAuth extends Facade
{
    protected static function getFacadeClass()
    {
        return 'fssy\jwt\JwtAuth';
    }
}
