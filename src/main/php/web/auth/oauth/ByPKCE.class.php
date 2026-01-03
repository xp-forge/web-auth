<?php namespace web\auth\oauth;

use lang\IllegalArgumentException;

/** @test web.auth.unittest.ByPKCETest */
class ByPKCE extends Credentials {
  private $challenge, $method;

  /**
   * Creates credentials with a client ID and method.
   * Support the `S256` and `plain` methods.
   *
   * @param  string $clientId
   * @param  string $method
   * @throws lang.IllegalArgumentException
   */
  public function __construct($clientId, $method) {
    parent::__construct($clientId);

    if ('S256' === $method) {
      $this->challenge= fn($verifier) => JWT::encode(hash('sha256', $verifier, true));
      $this->method= 'S256';
    } else if ('plain' === $method) {
      $this->challenge= fn($verifier) => $verifier;
      $this->method= 'plain';
    } else {
      throw new IllegalArgumentException('Unsupported method '.$method);
    }
  }

  /** @return string */
  public function method() { return $this->method; }

  /** Returns authorization seed */
  public function seed(): array {
    static $UNRESERVED= 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

    $random= random_bytes(64);
    $verifier= '';
    for ($i= 0; $i < 64; $i++) {
      $verifier.= $UNRESERVED[ord($random[$i]) % 66];
    }
    return ['verifier' => $verifier];
  }

  /** Returns parameters to be passed on to authorization */
  public function pass(array $seed): array {
    return [
      'code_challenge'        => ($this->challenge)($seed['verifier']),
      'code_challenge_method' => $this->method,
    ];
  }

  /** Returns parameters to be used in authentication process */
  public function params(string $endpoint, array $seed= []): array {
    return [
      'client_id'     => $this->key,
      'code_verifier' => $seed['verifier'],
    ];
  }
}