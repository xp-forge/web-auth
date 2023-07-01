<?php namespace web\auth\oauth;

use lang\IllegalArgumentException;
use util\UUID;

class ByCertificate extends Credentials {
  private $fingerprint, $key;

  /**
   * Creates a new certificate
   *
   * @param  string $clientId
   * @param  string $fingerprint
   * @param  var $key Anything supported by `openssl_pkey_get_private()`
   * @throws lang.IllegalArgumentException
   */
  public function __construct($clientId, $fingerprint, $key) {
    parent::__construct($clientId);
    $this->fingerprint= $fingerprint;
    if (false === ($this->key= openssl_pkey_get_private($key))) {
      throw new IllegalArgumentException(openssl_error_string());
    }
  }

  public function params(string $endpoint): array {
    $time= time();
    $jwt= new JWT(['alg' => 'RS256', 'typ' => 'JWT', 'x5t' => JWT::base64(hex2bin($this->fingerprint))], [
      'aud' => $endpoint,
      'exp' => $time + 3600,
      'iss' => $this->clientId,
      'jti' => UUID::timeUUID()->hashCode(),
      'nbf' => $time,
      'sub' => $this->clientId,
    ]);

    return [
      'client_id'             => $this->clientId,
      'client_assertion'      => $jwt->sign($this->key),
      'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    ];
  }
}