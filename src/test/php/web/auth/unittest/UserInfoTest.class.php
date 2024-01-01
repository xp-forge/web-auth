<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use test\{Assert, Before, Expect, Test, Values};
use web\auth\{UserInfo, AuthenticationError};

class UserInfoTest {
  private $returned;

  #[Before]
  public function returned() {
    $this->returned= function($source) { return $source; };
  }

  #[Test]
  public function can_create_with_supplier() {
    new UserInfo($this->returned);
  }

  #[Test]
  public function fetch() {
    $fixture= new UserInfo($this->returned);
    Assert::equals(['id' => 'root'], $fixture(['id' => 'root']));
  }

  #[Test, Expect(AuthenticationError::class)]
  public function fetch_raises_exception_when_endpoint_fails() {
    $fixture= new UserInfo(function($source) {
      throw new AuthenticationError('Internal Server Error');
    });
    $fixture(['id' => 6100]);
  }

  #[Test]
  public function map_functions_executed() {
    $fixture= (new UserInfo($this->returned))
      ->map(function($user) { return ['first' => $user]; })
      ->map(function($user) { return ['second' => $user, 'aggregated' => true]; })
    ;
    Assert::equals(
      ['second' => ['first' => ['id' => 6100]], 'aggregated' => true],
      $fixture(['id' => 6100])
    );
  }

  #[Test]
  public function map_generators_executed() {
    $fixture= (new UserInfo($this->returned))
      ->map(function($user) { yield 'first' => $user; })
      ->map(function($user) { yield 'second' => $user; yield 'aggregated' => true; })
    ;
    Assert::equals(
      ['second' => ['first' => ['id' => 6100]], 'aggregated' => true],
      $fixture(['id' => 6100])
    );
  }

  #[Test]
  public function map_functions_have_access_to_result() {
    $fixture= (new UserInfo($this->returned))->map(function($user, $result) {
      return ['user' => $result->fetch(), 'token' => $result->token()];
    });
    Assert::equals(
      ['user' => ['id' => 6100], 'token' => 'TOKEN'],
      $fixture(new class() {
        public function fetch() { return ['id' => 6100]; }
        public function token() { return 'TOKEN'; }
      })
    );
  }

  #[Test, Expect(AuthenticationError::class)]
  public function map_wraps_invocation_exceptions() {
    $fixture= (new UserInfo($this->returned))->map(function($user, $result) {
      throw new IllegalStateException('Test');
    });
    $fixture(['id' => 6100]);
  }

  #[Test, Expect(AuthenticationError::class)]
  public function map_wraps_supplier_exceptions() {
    $fixture= new UserInfo(function($result) {
      throw new IllegalStateException('Test');
    });
    $fixture(['id' => 6100]);
  }

  #[Test]
  public function peek_function_executed() {
    $invoked= [];
    $fixture= (new UserInfo($this->returned))->peek(function($user, $result) use(&$invoked) {
      $invoked[]= [$user, $result];
    });
    $user= $fixture(['id' => 6100]);

    Assert::equals(['id' => 6100], $user);
    Assert::equals([[['id' => 6100], ['id' => 6100]]], $invoked);
  }
}