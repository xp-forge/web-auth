<?php namespace web\auth\oauth;

use util\Secret;

class Token {
  private $key, $secret;

  public function __construct($key, $secret) {
    $this->key= $key instanceof Secret ? $key : new Secret($key);
    $this->secret= $secret instanceof Secret ? $secret : new Secret($secret);
  }

  public function key() { return $this->key; }

  public function secret() { return $this->secret; }
}