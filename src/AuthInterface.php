<?php
declare(strict_types=1);

namespace fssy\jwt;

/**
 * Interface AuthInterface
 * @package app\common\utils\auth
 */
interface AuthInterface
{
    /**
     * Issues token
     * @param int $id id
     * @param int $duration duration
     * @return string 返回签发的token
     */
    public function issueToken(int $id, int $duration = 0): string;

    /**
     * Retrieves the uid from the token and return a negative number on failure
     * @param string $token token
     * @return int
     */
    public function getId(string $token): int;
}
