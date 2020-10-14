<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use unittest\Assert;
use web\auth\Basic;
use web\filters\Invocation;
use web\io\{TestInput, TestOutput};
use web\{Request, Response};

class BasicTest {
  const REALM = 'Testing';
  const AUTHORIZATION = ['Authorization' => 'Basic dGVzdDpzZWNyZXQ='];

  private $login;

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
    $this->login= function($user, $secret) {
      return 'test' === $user && $secret->equals('secret') ? ['username' => 'test'] : null;
    };
  }

  #[Test]
  public function can_create() {
    new Basic(self::REALM, $this->login);
  }

  #[Test]
  public function required() {
    $auth= new Basic(self::REALM, $this->login);
    $this->handle(self::AUTHORIZATION, $auth->required(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'];
    }));

    Assert::equals('test', $user);
  }

  #[Test]
  public function handler_not_invoked_if_required_auth_missing() {
    $auth= new Basic(self::REALM, $this->login);
    $this->handle([], $auth->required(function($req, $res) {
      throw new IllegalStateException('Should not be reached');
    }));
  }

  #[Test]
  public function optional_with_authorization() {
    $auth= new Basic(self::REALM, $this->login);
    $this->handle(self::AUTHORIZATION, $auth->optional(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'] ?? 'guest';
    }));

    Assert::equals('test', $user);
  }

  #[Test]
  public function optional_without_authorization() {
    $auth= new Basic(self::REALM, $this->login);
    $this->handle([], $auth->optional(function($req, $res) use(&$user) {
      $user= $req->value('user')['username'] ?? 'guest';
    }));

    Assert::equals('guest', $user);
  }

  #[Test]
  public function yields_401_and_www_authenticate_without_authorization() {
    $auth= new Basic(self::REALM, $this->login);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $auth->filter($req, $res, new Invocation(function($req, $res) {
      throw new IllegalStateException('Handler should not be called');
    }));

    Assert::equals(
      [401, 'Basic realm="'.self::REALM.'"'],
      [$res->status(), $res->headers()['WWW-Authenticate']]
    );
  }

  #[Test, Values(['Bearer TOKEN', 'Basic NOT.BASE64', 'Basic Tk9fQ09MT04=', 'Basic dGVzdDpJTkNPUlJFQ1Q', 'Basic SU5DT1JSRUNUOnNlY3JldA=='])]
  public function yields_401_and_www_authenticate_with_incorrect($authorization) {
    $auth= new Basic(self::REALM, $this->login);

    $req= new Request(new TestInput('GET', '/', ['Authorization' => $authorization]));
    $res= new Response(new TestOutput());
    $auth->filter($req, $res, new Invocation(function($req, $res) {
      throw new IllegalStateException('Handler should not be called');
    }));

    Assert::equals(
      [401, 'Basic realm="'.self::REALM.'"'],
      [$res->status(), $res->headers()['WWW-Authenticate']]
    );
  }

  #[Test]
  public function passes_user() {
    $auth= new Basic(self::REALM, $this->login);

    $req= new Request(new TestInput('GET', '/', self::AUTHORIZATION));
    $res= new Response(new TestOutput());
    $auth->filter($req, $res, new Invocation(function($req, $res) {
      $res->send('Hello @'.$req->value('user')['username'], 'text/plain');
    }));

    Assert::equals(
      [200, 'Hello @test'],
      [$res->status(), trim(strstr($res->output()->bytes(), "\r\n\r\n"))]
    );
  }
}