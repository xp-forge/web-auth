<?php namespace web\auth\oauth;

use lang\IllegalStateException;

/**
 * Very simple JWT implementation (only supporting `RS256`)
 *
 * @see  https://tools.ietf.org/html/rfc7519
 * @see  https://developer.okta.com/blog/2019/02/04/create-and-verify-jwts-in-php
 * @test web.auth.unittest.JWTTest
 * @ext  openssl
 */
class JWT {
  private $header, $payload;

  /** Creates a new JWT with a given header and payload */
  public function __construct(array $header, array $payload) {
    $this->header= ['alg' => 'RS256'] + $header;
    $this->payload= $payload;
  }

  /** @return [:string] */
  public function header() { return $this->header; }

  /** @return [:string] */
  public function payload() { return $this->payload; }

  /**
   * Returns registered and custom claims, or NULL if there is no claim
   * present by the given name in the payload.
   *
   * @return var
   */
  public function claim(string $name) { return $this->payload[$name] ?? null; }

  /** URL-safe Base64 encoding */
  public static function encode(string $input): string {
    return strtr(rtrim(base64_encode($input), '='), '+/', '-_');
  }

  /** URL-safe Base64 decoding */
  public static function decode(string $input): string {
    return base64_decode(strtr($input, '-_', '+/'));
  }

  /**
   * Sign JWT with a private key and return token
   *
   * @param  string|OpenSSLAsymmetricKey $privateKey
   * @return string
   * @throws lang.IllegalStateException if signing fails
   */
  public function sign($privateKey): string {
    $input= self::encode(json_encode($this->header)).'.'.self::encode(json_encode($this->payload));

    // Hardcode SHA256 signing via OpenSSL here, would need algorithm-based
    // handling in order for this to be a full implementation, see e.g.
    // https://github.com/firebase/php-jwt/blob/v6.2.0/src/JWT.php#L220
    if (!openssl_sign($input, $signature, $privateKey, 'SHA256')) {
      throw new IllegalStateException(openssl_error_string());
    }

    return $input.'.'.self::encode($signature);
  }

  /** Helper to parse */
  private static function parse($token, $publicKey) {
    $parts= explode('.', $token, 3);
    if (3 !== sizeof($parts)) {
      return [null, 'Expected [header].[payload].[signature]'];
    }

    // Restrict supported algorithms to RS256, see comment in sign() above!
    $header= json_decode(self::decode($parts[0]), true);
    if (json_last_error()) {
      return [null, 'Header parsing error: '.json_last_error_msg()];
    } else if ('RS256' !== ($alg= $header['alg'] ?? '(null)')) {
      return [null, 'Unsupported algorithm '.$alg];
    }

    $payload= json_decode(self::decode($parts[1]), true);
    if (json_last_error()) {
      return [null, 'Payload parsing error: '.json_last_error_msg()];
    }

    // Returns 1 if the signature is correct, 0 if it is incorrect, and -1 or false on error.
    if (1 !== openssl_verify($parts[0].'.'.$parts[1], self::decode($parts[2]), $publicKey, 'SHA256')) {
      return [null, 'Signature mismatch: '.openssl_error_string()];
    }

    return [new self($header, $payload), null];
  }

  /**
   * Parse token into a JWT, verifying its signature with the public key
   *
   * @param  ?string $token
   * @param  string|OpenSSLAsymmetricKey $publicKey
   * @return self
   * @throws lang.IllegalStateException if verification fails
   */
  public static function from(?string $token, $publicKey): self {
    [$jwt, $err]= self::parse($token ?? '', $publicKey);

    // TODO (PHP 8): Migrate to throw expressions
    return $jwt ?? (function() use($err) { throw new IllegalStateException($err); })();
  }

  /**
   * Try to parse token into a JWT and verify its signature with the public key
   *
   * @param  ?string $token
   * @param  string|OpenSSLAsymmetricKey $publicKey
   * @return ?self
   */
  public static function tryFrom(?string $token, $publicKey): ?self {
    [$jwt, $err]= self::parse($token  ?? '', $publicKey);
    return $jwt;
  }
}