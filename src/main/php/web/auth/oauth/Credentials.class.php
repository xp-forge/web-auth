<?php namespace web\auth\oauth;

abstract class Credentials {
  public $key;

  /**
   * Creates credentials with a client ID and secret
   *
   * @param  string $key
   * @param  string|util.Secret $secret
   */
  public function __construct($key) {
    $this->key= $key;
  }

  /** Returns parameters to be used in authentication process */
  public abstract function params(string $endpoint, int $time= null): array;
}