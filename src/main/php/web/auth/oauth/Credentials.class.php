<?php namespace web\auth\oauth;

abstract class Credentials {
  public $clientId;

  /**
   * Creates credentials with a client ID and secret
   *
   * @param  string $clientId
   * @param  string|util.Secret $secret
   */
  public function __construct($clientId) {
    $this->clientId= $clientId;
  }

  /** Returns parameters to be used in authentication process */
  public abstract function params(string $endpoint, int $time= null): array;
}