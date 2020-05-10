<?php
declare(strict_types=1);

namespace fssy\jwt;

use fssy\jwt\exception\TokenDoesNotExistException;
use fssy\jwt\exception\TokenDoesNotMatchTheSceneException;
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
    private string $issuedBy = 'example.com';

    /**
     * Configures the audience (aud claim)
     * @var string
     */
    private string $permittedFor = 'example.org';

    /**
     * Configures the id (jti claim), replicating as a header item
     * @var string
     */
    private string $identifiedBy = 'identifiedBy';

    /**
     * Configures the time that the token was issue (iat claim)
     * @var int
     */
    private int $issuedAt;

    /**
     * Configures the time that the token can be used (nbf claim)
     * @var int
     */
    private int $canOnlyBeUsedAfter;

    /**
     * Configures the salt for token generating
     * @var string
     */
    private string $salt = 'salt';

    /**
     * Configures the use of token scenarios
     * @var string
     */
    private string $scene = 'default';

    public function __construct(
        string $issuedBy = '',
        string $permittedFor = '',
        string $identifiedBy = '',
        int $issuedAt = 0,
        int $canOnlyBeUsedAfter = 0,
        string $salt = '',
        string $scene = 'default'
    ) {
        $this->issuedBy = $issuedBy ?: Env::get('jwt.iss', $this->issuedBy);
        $this->permittedFor = $permittedFor ?: Env::get('jwt.aud', $this->permittedFor);
        $this->identifiedBy = $identifiedBy ?: Env::get('jwt.jti', $this->identifiedBy);
        $this->issuedAt = $issuedAt ?: time();
        $this->canOnlyBeUsedAfter = $canOnlyBeUsedAfter ?: time();
        $this->salt = $salt ?: Env::get('jwt.salt', $this->salt);
        $this->scene = $scene;
    }


    /**
     * @inheritDoc
     */
    public function issueToken(string $id, int $duration = 0): string
    {
        return (string)(new Builder())->issuedBy($this->issuedBy)
            ->permittedFor($this->permittedFor)
            ->identifiedBy($this->identifiedBy, true)
            ->issuedAt($this->issuedAt)
            ->canOnlyBeUsedAfter($this->canOnlyBeUsedAfter)
            ->expiresAt(time() + $duration)
            ->withClaim('id', $id)
            ->withClaim('scene', $this->scene)
            ->getToken(new Sha256(), new Key($this->salt));
    }

    /**
     * @inheritDoc
     * @throws TokenDoesNotExistException
     * @throws TokenIsNotValidException
     * @throws TokenExpiredException
     * @throws TokenDoesNotMatchTheSceneException
     */
    public function getId(string $token): string
    {
        if (!$token) {
            throw new TokenDoesNotExistException();
        }

        // Verifies the token signature
        $token = (new Parser())->parse($token);
        if (!$token->verify(new Sha256(), $this->salt)) {
            throw new TokenIsNotValidException();
        }

        // Verifies the token validity
        $data = new ValidationData();
        $data->setIssuer($this->issuedBy);
        $data->setAudience($this->permittedFor);
        $data->setId($this->identifiedBy);
        if (!$token->validate($data)) {
            throw new TokenExpiredException();
        }

        // verifies the use of token scenarios
        if ($this->scene != $token->getClaim('scene')) {
            throw new TokenDoesNotMatchTheSceneException();
        }

        return $token->getClaim('id');
    }

    /**
     * Sets the scene
     * @param string $scene scene
     * @return $this
     */
    public function setScene(string $scene): JwtAuth
    {
        $this->scene = $scene;
        return $this;
    }

    /**
     * Gets the scene
     * @return string
     */
    public function getScene()
    {
        return $this->scene;
    }
}
