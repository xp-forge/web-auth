<?php namespace web\auth\oauth\unittest;

use lang\IllegalStateException;
use unittest\{Expect, Test, TestCase, Values};
use web\auth\oauth\{OAuth2Flow, Session};
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;
use web\{Request, Response};

class OAuth2FlowTest extends TestCase {
  const AUTH   = 'https://example.com/oauth/authorize';
  const TOKENS = 'https://example.com/oauth/access_token';
  const ID     = 'bf396750';
  const SECRET = '5ebe2294ecd0e0f08eab7690d2a6ee69';

  #[Test]
  public function can_create() {
    new OAuth2Flow(self::AUTH, self::TOKENS, [self::ID, self::SECRET]);
  }

  #[Test, Values([[['user']], [['user', 'openid']]])]
  public function redirects_to_auth_and_passes_scope($scope) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, [self::ID, self::SECRET], $scope);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();

    $fixture->authenticate($req, $res, $session);

    $url= sprintf(
      '%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s',
      self::AUTH,
      self::ID,
      urlencode('http://localhost/'),
      implode('+', $scope),
      $session->value(OAuth2Flow::SESSION_KEY)
    );
    $this->assertEquals($url, $res->headers()['Location']);
  }

  #[Test]
  public function redirects_to_auth_when_previous_redirect_incomplete() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, [self::ID, self::SECRET]);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, 'PREVIOUS_STATE');

    $fixture->authenticate($req, $res, $session);

    $url= sprintf(
      '%s?response_type=code&client_id=%s&redirect_uri=%s&scope=user&state=%s',
      self::AUTH,
      self::ID,
      urlencode('http://localhost/'),
      $session->value(OAuth2Flow::SESSION_KEY)
    );
    $this->assertEquals($url, $res->headers()['Location']);
  }

  #[Test]
  public function gets_access_token_and_redirects_to_self() {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $state= 'SHARED_STATE';
    $fixture= newinstance(OAuth2Flow::class, [self::AUTH, self::TOKENS, [self::ID, self::SECRET]], [
      'token' => function($payload) use($token) { return $token; }
    ]);

    $req= new Request(new TestInput('GET', '/?state='.$state.'&code=SERVER_CODE'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, $state);

    $fixture->authenticate($req, $res, $session);

    $this->assertEquals('http://localhost/', $res->headers()['Location']);
    $this->assertEquals($token, $session->value(OAuth2Flow::SESSION_KEY));
  }

  #[Test, Expect(IllegalStateException::class)]
  public function raises_exception_on_state_mismatch() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, [self::ID, self::SECRET]);

    $req= new Request(new TestInput('GET', '/?state=SERVER_STATE&code=SERVER_CODE'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, 'CLIENT_STATE');

    $fixture->authenticate($req, $res, $session);
  }

  #[Test]
  public function returns_session() {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, [self::ID, self::SECRET]);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, $token);

    $this->assertInstanceOf(Session::class, $fixture->authenticate($req, $res, $session));
  }
}