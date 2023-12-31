<?php namespace web\auth\oauth;

use Iterator, Throwable;
use web\auth\AuthenticationError;

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
   * @param  (function(var): var)|(function(var, web.auth.oauth.Client): var) $function
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
   * @throws web.auth.AuthenticationError
   */
  public function __invoke($client) {
    $response= $client->fetch($this->endpoint);
    if ($response->status() >= 400) {
      throw new AuthenticationError('Unexpected status '.$response->status().' from '.$this->endpoint);
    }

    try {
      $value= $response->value();
      foreach ($this->map as $function) {
        $result= $function($value, $client);
        $value= $result instanceof Iterator ? iterator_to_array($result) : $result;
      }
      return $value;
    } catch (Throwable $t) {
      throw new AuthenticationError('Invoking mappers: '.$t->getMessage(), $t);
    }
  }
}