<?php namespace web\auth;

use Iterator, Throwable;
use web\auth\AuthenticationError;

/**
 * Retrieves details about the authenticated user from a given endpoint.
 *
 * @test  web.auth.unittest.UserInfoTest
 */
class UserInfo {
  private $supplier;
  private $map= [];

  /** @param function(var): var $supplier */
  public function __construct(callable $supplier) { $this->supplier= $supplier; }

  /**
   * Maps the user info using the given the function.
   *
   * @param  (function(var): var)|(function(var, var): var) $function
   * @return self
   */
  public function map(callable $function) {
    $this->map[]= $function;
    return $this;
  }

  /**
   * Peeks into the given results. Useful for debugging.
   *
   * @param  (function(var): void)|(function(var, var): void) $function
   * @return self
   */
  public function peek(callable $function) {
    $this->map[]= function($value, $result) use($function) {
      $function($value, $result);
      return $value;
    };
    return $this;
  }

  /**
   * Fetches the user info and maps the returned value.
   * 
   * @param  var $result Authentication flow result
   * @return var The user object
   * @throws web.auth.AuthenticationError
   */
  public function __invoke($result) {
    try {
      $value= ($this->supplier)($result);
      foreach ($this->map as $function) {
        $result= $function($value, $result);
        $value= $result instanceof Iterator ? iterator_to_array($result) : $result;
      }
      return $value;
    } catch (AuthenticationError $e) {
      throw $e;
    } catch (Throwable $t) {
      throw new AuthenticationError('Invoking mappers: '.$t->getMessage(), $t);
    }
  }
}