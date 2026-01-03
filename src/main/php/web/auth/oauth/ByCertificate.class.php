<?php namespace web\auth\oauth;

use lang\IllegalArgumentException;
use util\UUID;

/**
 * JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 * Authorization Grants
 *
 * @test web.auth.unittest.ByCertificateTest
 * @see  https://tools.ietf.org/html/rfc7523
 * @ext  openssl
 */
class ByCertificate extends Credentials {
  private $fingerprint, $privateKey, $validity;

  /**
   * Creates a new certificate
   *
   * @param  string $clientId
   * @param  string $fingerprint
   * @param  var $privateKey Anything supported by `openssl_pkey_get_private()`
   * @param  int $validity
   * @throws lang.IllegalArgumentException
   */
  public function __construct($clientId, $fingerprint, $privateKey, $validity= 3600) {
    parent::__construct($clientId);
    $this->fingerprint= str_replace(':', '', $fingerprint);
    $this->validity= $validity;

    if (false === ($this->privateKey= openssl_pkey_get_private($privateKey))) {
      throw new IllegalArgumentException(openssl_error_string());
    }
  }

  /** Returns parameters to be used in authentication process */
  public function params(string $endpoint, array $seed= []): array {
    $time= $seed['time'] ?? time();
    $jwt= new JWT(['alg' => 'RS256', 'typ' => 'JWT', 'x5t' => JWT::encode(hex2bin($this->fingerprint))], [
      'aud' => $endpoint,
      'exp' => $time + $this->validity,
      'iss' => $this->key,
      'jti' => UUID::timeUUID()->hashCode(),
      'nbf' => $time,
      'sub' => $this->key,
    ]);

    return [
      'client_id'             => $this->key,
      'client_assertion'      => $jwt->sign($this->privateKey),
      'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    ];
  }
}