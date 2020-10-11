<?php namespace web\auth\unittest;

use unittest\Assert;
use web\Handler;
use web\auth\{Authentication, Flow};
use web\session\ForTesting;

class AuthenticationTest {
  private $sessions, $flow;

  #[Before]
  public function setUp() {
    $this->sessions= new ForTesting();
    $this->flow= new class() implements Flow {
      public function authenticate($req, $res, $invocation) {
        // ...
      }
    };
  }

  #[Test]
  public function can_create() {
    new Authentication($this->flow, $this->sessions);
  }

  #[Test]
  public function required() {
    $auth= new Authentication($this->flow, $this->sessions);
    Assert::instance(Handler::class, $auth->required(function($req, $res) {
      // ...
    }));
  }
}