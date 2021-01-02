<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use unittest\Assert;
use web\auth\{SessionBased, Flow};
use web\io\{TestInput, TestOutput};
use web\session\{ForTesting, Transport};
use web\{Request, Response};

class SessionBasedTest {
  private $sessions;

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

  private function authenticate($result) {
    return newinstance(Flow::class, [], [
      'authenticate' => function($req, $res, $invocation) use($result) {
        return $result;
      }
    ]);
  }

  #[Before]
  public function sessions() {
    $this->sessions= new ForTesting();
  }

  #[Test]
  public function can_create() {
    new SessionBased($this->authenticate(null), $this->sessions);
  }

  #[Test]
  public function required() {
    $session= $this->sessions->create();
    $session->register('user', ['username' => 'test']);

    $auth= new SessionBased($this->authenticate(null), $this->sessions);
    $this->handle(['Cookie' => 'session='.$session->id()], $auth->required(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'];
    }));

    Assert::equals('test', $user);
  }

  #[Test]
  public function handler_not_invoked_if_required_auth_missing() {
    $auth= new SessionBased($this->authenticate(null), $this->sessions);
    $this->handle([], $auth->required(function($req, $res) {
      throw new IllegalStateException('Should not be reached');
    }));
  }

  #[Test]
  public function optional_without_session() {
    $auth= new SessionBased($this->authenticate(null), $this->sessions);
    $this->handle([], $auth->optional(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'] ?? 'guest';
    }));

    Assert::equals('guest', $user);
  }

  #[Test]
  public function optional_with_session() {
    $session= $this->sessions->create();
    $session->register('user', ['username' => 'test']);

    $auth= new SessionBased($this->authenticate(null), $this->sessions);
    $this->handle(['Cookie' => 'session='.$session->id()], $auth->optional(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'] ?? 'guest';
    }));

    Assert::equals('test', $user);
  }

  #[Test]
  public function optional_with_session_without_user() {
    $session= $this->sessions->create();

    $auth= new SessionBased($this->authenticate(null), $this->sessions);
    $this->handle(['Cookie' => 'session='.$session->id()], $auth->optional(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'] ?? 'guest';
    }));

    Assert::equals('guest', $user);
  }

  #[Test]
  public function passes_user() {
    $user= ['username' => 'test'];

    $auth= new SessionBased($this->authenticate($user), $this->sessions);
    $this->handle([], $auth->required(function($req, $res) use(&$passed) {
      $passed= $req->value('user');
    }));

    Assert::equals($user, $passed);
  }

  #[Test]
  public function marshals_user_to_session() {
    $session= $this->sessions->create();

    $auth= new SessionBased($this->authenticate(new User(1, 'test')), $this->sessions);
    $this->handle(['Cookie' => 'session='.$session->id()], $auth->required(function($req, $res) { }));

    Assert::equals(['__type' => User::class, 'id' => 1, 'username' => 'test'], $session->value('user'));
  }

  #[Test]
  public function unmarshals_user_from_session() {
    $session= $this->sessions->create();
    $session->register('user', ['__type' => User::class, 'id' => 1, 'username' => 'test']);

    $auth= new SessionBased($this->authenticate(null), $this->sessions);
    $this->handle(['Cookie' => 'session='.$session->id()], $auth->required(function($req, $res) use(&$user) {
      $user= $req->value('user');
    }));

    Assert::equals(new User(1, 'test'), $user);
  }

  #[Test]
  public function session_is_attached_after_authentication() {
    $user= ['username' => 'test'];
    $attached= null;

    $auth= new SessionBased($this->authenticate($user), $this->sessions->via(newinstance(Transport::class, [], [
      'locate' => function($sessions, $request) { return null; },
      'attach' => function($sessions, $response, $session) use(&$attached) { $attached= $session; },
      'detach' => function($sessions, $response, $session) { }
    ])));
    $this->handle([], $auth->required(function($req, $res) { }));

    Assert::notEquals(null, $attached);
    Assert::equals($user, $attached->value('user'));
  }
}