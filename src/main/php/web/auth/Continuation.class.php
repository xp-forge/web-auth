<?php namespace web\auth;

class Continuation {
  public $uri, $value;

  /**
   * Creates a new continuation
   *
   * @param  string $uri
   * @param  var $value
   */
  public function __construct($uri, $value= null) {
    $this->uri= $uri;
    $this->value= $value;
  }
}