<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use test\{Assert, Before, Expect, Test, Values};
use web\auth\{UserInfo, AuthenticationError};

class UserInfoTest {
  const USER= ['id' => 6100];

  private $returned;


  /** @return iterable */
  private function mappers() {
    $instance= new class() {
      public function first($user) { return ['first' => $user]; }
      public function second($user) { return ['second' => $user, 'aggregated' => true]; }
    };
    yield [
      [$instance, 'first'],
      [$instance, 'second']
    ];
    yield [
      fn($user) => ['first' => $user],
      fn($user) => ['second' => $user, 'aggregated' => true],
    ];
    yield [
      function($user) { yield 'first' => $user; },
      function($user) { yield 'second' => $user; yield 'aggregated' => true; },
    ];
    yield [
      new class() { public function __invoke($user) { return ['first' => $user]; }},
      new class() { public function __invoke($user) { return ['second' => $user, 'aggregated' => true]; }},
    ];
  }

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
    $fixture(self::USER);
  }

  #[Test, Values(from: 'mappers')]
  public function map_functions_executed($first, $second) {
    $fixture= (new UserInfo($this->returned))->map($first)->map($second);
    Assert::equals(
      ['second' => ['first' => self::USER], 'aggregated' => true],
      $fixture(self::USER)
    );
  }

  #[Test]
  public function map_functions_have_access_to_result() {
    $fixture= (new UserInfo($this->returned))->map(function($user, $result) {
      return ['user' => $result->fetch(), 'token' => $result->token()];
    });
    Assert::equals(
      ['user' => self::USER, 'token' => 'TOKEN'],
      $fixture(new class(self::USER) {
        private $user;
        public function __construct($user) { $this->user= $user; }
        public function fetch() { return $this->user; }
        public function token() { return 'TOKEN'; }
      })
    );
  }

  #[Test, Expect(AuthenticationError::class)]
  public function map_wraps_invocation_exceptions() {
    $fixture= (new UserInfo($this->returned))->map(function($user, $result) {
      throw new IllegalStateException('Test');
    });
    $fixture(self::USER);
  }

  #[Test, Expect(AuthenticationError::class)]
  public function map_wraps_supplier_exceptions() {
    $fixture= new UserInfo(function($result) {
      throw new IllegalStateException('Test');
    });
    $fixture(self::USER);
  }

  #[Test]
  public function peek_function_executed() {
    $invoked= [];
    $fixture= (new UserInfo($this->returned))->peek(function($user, $result) use(&$invoked) {
      $invoked[]= [$user, $result];
    });
    $user= $fixture(self::USER);

    Assert::equals(self::USER, $user);
    Assert::equals([[self::USER, self::USER]], $invoked);
  }
}