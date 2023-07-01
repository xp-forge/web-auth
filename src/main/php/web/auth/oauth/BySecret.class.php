<?php namespace web\auth\oauth;

use util\Secret;

class BySecret extends Credentials {
  protected $secret;

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

  /** Returns parameter to be used in authentication process */
  public function params(string $endpoint): array {
    return [
      'client_id'     => $this->clientId,
      'client_secret' => $this->secret->reveal(),
    ];
  }
}