<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use unittest\Assert;
use web\auth\{SessionBased, Flow};
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;
use web\{Request, Response};

class SessionBasedTest {
  private $sessions, $flow;

  /**
   * Invokes handle() function
   *
   * @param  [:var] $headers
   * @param  web.Handler $handler
   */
  private function handle($headers, $handler) {
    $req= new Request(new TestInput('GET', '/', $headers));
    $res= new Response(new TestOutput());
    $handler->handle($req, $res);
  }

  #[Before]
  public function setUp() {
    $this->sessions= new ForTesting();
    $this->flow= new class() extends Flow {
      public function authenticate($req, $res, $invocation) {
        // ...
      }
    };
  }

  #[Test]
  public function can_create() {
    new SessionBased($this->flow, $this->sessions);
  }

  #[Test]
  public function required() {
    $session= $this->sessions->create();
    $session->register('user', ['username' => 'test']);

    $auth= new SessionBased($this->flow, $this->sessions);
    $this->handle(['Cookie' => 'session='.$session->id()], $auth->required(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'];
    }));

    Assert::equals('test', $user);
  }

  #[Test]
  public function handler_not_invoked_if_required_auth_missing() {
    $auth= new SessionBased($this->flow, $this->sessions);
    $this->handle([], $auth->required(function($req, $res) {
      throw new IllegalStateException('Should not be reached');
    }));
  }

  #[Test]
  public function optional_without_session() {
    $auth= new SessionBased($this->flow, $this->sessions);
    $this->handle([], $auth->optional(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'] ?? 'guest';
    }));

    Assert::equals('guest', $user);
  }

  #[Test]
  public function optional_with_session() {
    $session= $this->sessions->create();
    $session->register('user', ['username' => 'test']);

    $auth= new SessionBased($this->flow, $this->sessions);
    $this->handle(['Cookie' => 'session='.$session->id()], $auth->optional(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'] ?? 'guest';
    }));

    Assert::equals('test', $user);
  }

  #[Test]
  public function optional_with_session_without_user() {
    $session= $this->sessions->create();

    $auth= new SessionBased($this->flow, $this->sessions);
    $this->handle(['Cookie' => 'session='.$session->id()], $auth->optional(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'] ?? 'guest';
    }));

    Assert::equals('guest', $user);
  }
}