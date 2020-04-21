<?php
declare(strict_types=1);

namespace fssy\jwt;

use fssy\jwt\exception\TokenDoesNotExistException;
use fssy\jwt\exception\TokenExpiredException;
use fssy\jwt\exception\TokenIsNotValidException;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\ValidationData;
use think\facade\Env;

/**
 * Class JWTAuth
 * @package app\common\utils\auth\jwt
 */
class JwtAuth implements AuthInterface
{

    /**
     * Configures the issuer (iss claim)
     * @var string
     */
    private $issuedBy;

    /**
     * Configures the audience (aud claim)
     * @var string
     */
    private $permittedFor;

    /**
     * Configures the id (jti claim), replicating as a header item
     * @var string
     */
    private $identifiedBy;

    /**
     * Configures the time that the token was issue (iat claim)
     * @var int
     */
    private $issuedAt;

    /**
     * Configures the time that the token can be used (nbf claim)
     * @var int
     */
    private $canOnlyBeUsedAfter;

    /**
     * Configures the salt for token generating
     * @var string
     */
    private $salt;

    public function __construct(
        string $issuedBy = '',
        string $permittedFor = '',
        string $identifiedBy = '',
        int $issuedAt = 0,
        int $canOnlyBeUsedAfter = 0,
        string $salt = ''
    )
    {
        $this->issuedBy = $issuedBy ?: Env::get('jwt.iss', 'example.com');
        $this->permittedFor = $permittedFor ?: Env::get('jwt.aud', 'example.org');
        $this->identifiedBy = $identifiedBy ?: Env::get('jwt.jti', 'seworlsfjslfxxdsfj');
        $this->issuedAt = $issuedAt ?: time();
        $this->canOnlyBeUsedAfter = $canOnlyBeUsedAfter ?: time();
        $this->salt = $salt ?: Env::get('jwt.salt', '12323ljdsalfsdalfjlxcvjdfhoewro');
    }


    /**
     * @inheritDoc
     */
    public function issueToken(int $id, int $duration = 0): string
    {
        return (string)(new Builder())->issuedBy($this->issuedBy)
            ->permittedFor($this->permittedFor)
            ->identifiedBy($this->identifiedBy, true)
            ->issuedAt($this->issuedAt)
            ->canOnlyBeUsedAfter($this->canOnlyBeUsedAfter)
            ->expiresAt(time() + $duration)
            ->withClaim('id', $id)
            ->getToken(new Sha256(), new Key($this->salt));
    }

    /**
     * @inheritDoc
     * @throws TokenDoesNotExistException
     * @throws TokenIsNotValidException
     * @throws TokenExpiredException
     */
    public function getId(string $token): int
    {
        if (!$token) {
            throw new TokenDoesNotExistException();
        }

        // Verifies signature
        $token = (new Parser())->parse($token);
        if (!$token->verify(new Sha256(), $this->salt)) {
            throw new TokenIsNotValidException();
        }

        // Verifies token validity
        $data = new ValidationData();
        $data->setIssuer($this->issuedBy);
        $data->setAudience($this->permittedFor);
        $data->setId($this->identifiedBy);
        if (!$token->validate($data)) {
            throw new TokenExpiredException();
        }

        return (int)$token->getClaim('id');
    }
}
