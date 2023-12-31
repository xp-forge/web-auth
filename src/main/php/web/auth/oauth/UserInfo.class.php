<?php namespace web\auth\oauth;

use Iterator;
use peer\AuthenticationException;

/**
 * Retrieves details about the authenticated user from a given endpoint.
 *
 * @test  web.auth.unittest.UserInfoTest
 */
class UserInfo {
  private $endpoint;
  private $map= [];

  /**
   * Creates a new instance
   *
   * @param  string $endpoint
   */
  public function __construct($endpoint) {
    $this->endpoint= $endpoint;
  }

  /**
   * Maps the user info using the given the function.
   *
   * @param  function(var): var $function
   * @return self
   */
  public function map(callable $function) {
    $this->map[]= $function;
    return $this;
  }

  /**
   * Fetches the user info and maps the returned value.
   * 
   * @param  web.auth.oauth.Client $client
   * @return var
   * @throws peer.AuthenticationException
   */
  public function __invoke($client) {
    $response= $client->fetch($this->endpoint);
    if ($response->status() >= 400) {
      throw new AuthenticationException(
        'Unexpected status '.$response->status().' from '.$this->endpoint,
        self::class
      );
    }

    $value= $response->value();
    foreach ($this->map as $function) {
      $result= $function($value);
      $value= $result instanceof Iterator ? iterator_to_array($result) : $result;
    }
    return $value;
  }
}