<?php namespace web\auth\oauth;

use util\Secret;

class BySecret extends Credentials {
  private $secret;

  /**
   * Creates credentials with a client ID and secret
   *
   * @param  string $clientId
   * @param  string|util.Secret $secret
   */
  public function __construct($clientId, $secret) {
    parent::__construct($clientId);
    $this->secret= $secret instanceof Secret ? $secret : new Secret($secret);
  }

  /** @return util.Secret */
  public function secret() { return $this->secret; }

  /** Returns parameters to be used in authentication process */
  public function params(string $endpoint, array $seed= []): array {
    return [
      'client_id'     => $this->key,
      'client_secret' => $this->secret->reveal(),
    ];
  }
}