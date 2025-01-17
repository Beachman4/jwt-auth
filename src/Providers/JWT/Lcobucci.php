<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Providers\JWT;

use Carbon\Carbon;
use Exception;
use Illuminate\Support\Collection;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Keychain;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use ReflectionClass;
use Tymon\JWTAuth\Contracts\Providers\JWT;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class Lcobucci extends Provider implements JWT
{
    /**
     * @var \Lcobucci\JWT\Signer
     */
    protected $signer;

    /**
     * @var Configuration
     */
    protected $configuration;

    /**
     * Create the Lcobucci provider.
     *
     * @param  string  $secret
     * @param  string  $algo
     * @param  array  $keys
     *
     * @return void
     * @throws JWTException
     */
    public function __construct(
        $secret,
        $algo,
        array $keys
    ) {
        parent::__construct($secret, $algo, $keys);
        $this->signer = $this->getSigner();
    }

    /**
     * Signers that this provider supports.
     *
     * @var array
     */
    protected $signers = [
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
    ];

    /**
     * Create a JSON Web Token.
     *
     * @param  array  $payload
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     * @return string
     */
    public function encode(array $payload)
    {
        // Remove the signature on the builder instance first.
        $builder = $this->getConfiguration()->builder();

        try {
            foreach ($payload as $key => $value) {
                if ($key === 'iss') {
                    $builder->issuedBy($value);
                } else if ($key === 'nbf') {
                    $builder->canOnlyBeUsedAfter(\DateTimeImmutable::createFromMutable(Carbon::createFromTimestamp($value)));
                } else if ($key === 'jti') {
                    $builder->identifiedBy($value);
                } else if ($key === 'aud') {
                    $builder->permittedFor($value);
                } else if ($key === 'sub') {
                    $builder->relatedTo($value);
                } else if ($key === 'iat') {
                    $builder->issuedAt(\DateTimeImmutable::createFromMutable(Carbon::createFromTimestamp($value)));
                } else if ($key === 'exp') {
                    $builder->expiresAt(\DateTimeImmutable::createFromMutable(Carbon::createFromTimestamp($value)));
                }else {
                    $builder->withClaim($key, $value);
                }
            }
            return $builder->getToken($this->getConfiguration()->signer(), $this->getConfiguration()->signingKey())->toString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param  string  $token
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     * @return array
     */
    public function decode($token)
    {
        try {
            $jwt = $this->getConfiguration()->parser()->parse($token);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: '.$e->getMessage(), $e->getCode(), $e);
        }

        $constraints = $this->getConfiguration()->validationConstraints();

        if (! $this->getConfiguration()->validator()->validate($jwt, ...$constraints)) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }

        return (new Collection($jwt->claims()->all()))->map(function ($claim) {

            if ($claim instanceof \DateTimeImmutable) {
                return $claim->getTimestamp();
            }

            return is_object($claim) ? $claim->getValue() : $claim;
        })->toArray();
    }

    private function getConfiguration()
    {
        if ($this->isAsymmetric()) {
            $config = Configuration::forAsymmetricSigner($this->signer, $this->getSigningKey(), $this->getVerificationKey());
        } else {
            $config = Configuration::forSymmetricSigner($this->signer, $this->getSigningKey());
        }

        $config->setValidationConstraints(new SignedWith($config->signer(), $config->signingKey()));

        return $config;
    }

    /**
     * Get the signer instance.
     *
     * @throws \Tymon\JWTAuth\Exceptions\JWTException
     *
     * @return \Lcobucci\JWT\Signer
     */
    protected function getSigner()
    {
        if (! array_key_exists($this->algo, $this->signers)) {
            throw new JWTException('The given algorithm could not be found');
        }

        return new $this->signers[$this->algo];
    }

    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        $reflect = new ReflectionClass($this->signer);

        return $reflect->isSubclassOf(Rsa::class) || $reflect->isSubclassOf(Ecdsa::class);
    }

    /**
     * {@inheritdoc}
     */
    protected function getSigningKey()
    {
        return $this->isAsymmetric() ?
            InMemory::plainText($this->getPrivateKey(), $this->getPassphrase()) :
            InMemory::plainText($this->getSecret());
    }

    /**
     * {@inheritdoc}
     */
    protected function getVerificationKey()
    {
        return $this->isAsymmetric() ?
            InMemory::plainText($this->getPublicKey()) :
            InMemory::plainText($this->getSecret());
    }
}
