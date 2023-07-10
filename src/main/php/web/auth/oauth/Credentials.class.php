<?php namespace web\auth\oauth;

use lang\IllegalStateException;

abstract class Credentials {
  public static $UNSET;
  public $key;

  static function __static() {
    self::$UNSET= new class(null) extends Credentials {
      public function params(string $endpoint, int $time= null): array {
        throw new IllegalStateException('No credentials set');
      }
    };
  }

  /**
   * Creates credentials with a client ID
   *
   * @param  ?string $key
   */
  public function __construct($key) {
    $this->key= $key;
  }

  /** Returns parameters to be used in authentication process */
  public abstract function params(string $endpoint, int $time= null): array;
}