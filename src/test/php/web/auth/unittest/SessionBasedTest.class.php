<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use test\{Assert, Test};
use web\auth\{Flow, SessionBased};
use web\io\{TestInput, TestOutput};
use web\session\{ForTesting, ISession};
use web\{Request, Response};

class SessionBasedTest {

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
      'authenticate' => function($req, $res, $session) use($result) {
        if (isset($result)) return $result;

        // Redirect to SSO
        $session->transmit($res);
        $this->redirect($res, 'https://sso.example.com/', 'document.location.replace("%1$s");');
        return null;
      }
    ]);
  }

  #[Test]
  public function can_create() {
    new SessionBased($this->authenticate(null), new ForTesting());
  }

  #[Test]
  public function required() {
    $sessions= new ForTesting();
    $session= $sessions->create();
    $session->register('user', ['username' => 'test']);

    $auth= new SessionBased($this->authenticate(null), $sessions);
    $this->handle(['Cookie' => 'session='.$session->id()], $auth->required(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'];
    }));

    Assert::equals('test', $user);
  }

  #[Test]
  public function handler_not_invoked_if_required_auth_missing() {
    $auth= new SessionBased($this->authenticate(null), new ForTesting());
    $this->handle([], $auth->required(function($req, $res) {
      throw new IllegalStateException('Should not be reached');
    }));
  }

  #[Test]
  public function optional_without_session() {
    $auth= new SessionBased($this->authenticate(null), new ForTesting());
    $this->handle([], $auth->optional(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'] ?? 'guest';
    }));

    Assert::equals('guest', $user);
  }

  #[Test]
  public function optional_with_session() {
    $sessions= new ForTesting();
    $session= $sessions->create();
    $session->register('user', ['username' => 'test']);

    $auth= new SessionBased($this->authenticate(null), $sessions);
    $this->handle(['Cookie' => 'session='.$session->id()], $auth->optional(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'] ?? 'guest';
    }));

    Assert::equals('test', $user);
  }

  #[Test]
  public function optional_with_session_without_user() {
    $sessions= new ForTesting();
    $session= $sessions->create();

    $auth= new SessionBased($this->authenticate(null), $sessions);
    $this->handle(['Cookie' => 'session='.$session->id()], $auth->optional(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'] ?? 'guest';
    }));

    Assert::equals('guest', $user);
  }

  #[Test]
  public function passes_user() {
    $user= ['username' => 'test'];

    $auth= new SessionBased($this->authenticate($user), new ForTesting());
    $this->handle([], $auth->required(function($req, $res) use(&$passed) {
      $passed= $req->value('user');
    }));

    Assert::equals($user, $passed);
  }

  #[Test]
  public function passes_token() {
    $auth= new SessionBased($this->authenticate(['username' => 'test']), new ForTesting());
    $this->handle([], $auth->required(function($req, $res) use(&$token) {
      $token= $req->value('token');
    }));

    Assert::equals(SessionBased::TOKEN_LENGTH, strlen(base64_decode($token)));
  }

  #[Test]
  public function session_is_attached_when_redirecting() {
    $auth= new SessionBased($this->authenticate(null), newinstance(ForTesting::class, [], [
      'locate' => function($request) { return null; },
      'detach' => function($session, $response) { },
      'attach' => function($session, $response) use(&$attached) {
        $attached= $session;
        $attached->register('times', $attached->value('times', 0) + 1);
      },
    ]));
    $this->handle([], $auth->required(function($req, $res) { }));

    Assert::instance(ISession::class, $attached);
    Assert::equals(1, $attached->value('times'));
  }

  #[Test]
  public function session_is_attached_after_authentication() {
    $user= ['username' => 'test'];
    $attached= null;

    $auth= new SessionBased($this->authenticate($user), newinstance(ForTesting::class, [], [
      'locate' => function($request) { return null; },
      'detach' => function($session, $response) { },
      'attach' => function($session, $response) use(&$attached) {
        $attached= $session;
        $attached->register('times', $attached->value('times', 0) + 1);
      },
    ]));
    $this->handle([], $auth->required(function($req, $res) { }));

    Assert::instance(ISession::class, $attached);
    Assert::equals(1, $attached->value('times'));
    Assert::equals($user, $attached->value('auth')[1]);
  }
}