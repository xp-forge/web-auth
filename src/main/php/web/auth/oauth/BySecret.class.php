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

  /** Returns parameters to be used in authentication process */
  public function params(string $endpoint, int $time= null): array {
    return [
      'client_id'     => $this->clientId,
      'client_secret' => $this->secret->reveal(),
    ];
  }
}