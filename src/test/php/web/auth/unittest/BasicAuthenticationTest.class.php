<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use unittest\Assert;
use web\auth\BasicAuthentication;
use web\filters\Invocation;
use web\io\{TestInput, TestOutput};
use web\{Handler, Request, Response};

class BasicAuthenticationTest {
  const REALM = 'Testing';

  private $login;

  #[Before]
  public function setUp() {
    $this->login= function($user, $secret) {
      return 'test' === $user && $secret->equals('secret') ? ['username' => 'test'] : null;
    };
  }

  #[Test]
  public function can_create() {
    new BasicAuthentication(self::REALM, $this->login);
  }

  #[Test]
  public function required() {
    $auth= new BasicAuthentication(self::REALM, $this->login);
    Assert::instance(Handler::class, $auth->required(function($req, $res) {
      // ...
    }));
  }

  #[Test]
  public function yields_401_and_www_authenticate_without_authorization() {
    $auth= new BasicAuthentication(self::REALM, $this->login);

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
    $auth= new BasicAuthentication(self::REALM, $this->login);

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
    $auth= new BasicAuthentication(self::REALM, $this->login);

    $req= new Request(new TestInput('GET', '/', ['Authorization' => 'Basic dGVzdDpzZWNyZXQ=']));
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