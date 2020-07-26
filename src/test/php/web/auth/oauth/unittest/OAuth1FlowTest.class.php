<?php namespace web\auth\oauth\unittest;

use lang\IllegalStateException;
use unittest\TestCase;
use web\auth\oauth\{OAuth1Flow, Session};
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;
use web\{Request, Response};

class OAuth1FlowTest extends TestCase {
  const AUTH    = 'https://example.com/oauth';
  const ID      = 'bf396750';
  const SECRET  = '5ebe2294ecd0e0f08eab7690d2a6ee69';

  #[@test]
  public function can_create() {
    new OAuth1Flow(self::AUTH, [self::ID, self::SECRET]);
  }

  #[@test]
  public function fetches_request_token_then_redirects_to_auth() {
    $request= ['oauth_token' => 'REQUEST-TOKEN'];
    $fixture= newinstance(OAuth1Flow::class, [self::AUTH, [self::ID, self::SECRET]], [
      'request' => function($path, $token= null, $params= []) use($request) { return $request; }
    ]);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();

    $fixture->authenticate($req, $res, $session);

    $this->assertEquals(self::AUTH.'/authenticate?oauth_token=REQUEST-TOKEN', $res->headers()['Location']);
  }

  #[@test]
  public function exchanges_request_token_for_access_token() {
    $access= ['oauth_token' => 'ACCESS-TOKEN', 'oauth_token_secret' => 'XYZ', 'access' => true];
    $fixture= newinstance(OAuth1Flow::class, [self::AUTH, [self::ID, self::SECRET]], [
      'request' => function($path, $token= null, $params= []) use($access) { return $access; }
    ]);

    $req= new Request(new TestInput('GET', '/?oauth_token=REQUEST-TOKEN&oauth_verifier=ABC'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth1Flow::SESSION_KEY, ['oauth_token' => 'REQUEST-TOKEN']);

    $fixture->authenticate($req, $res, $session);

    $this->assertEquals('http://localhost/', $res->headers()['Location']);
    $this->assertEquals($access, $session->value(OAuth1Flow::SESSION_KEY));
  }

  #[@test, @expect(IllegalStateException::class)]
  public function raises_exception_on_state_mismatch() {
    $fixture= new OAuth1Flow(self::AUTH, [self::ID, self::SECRET]);

    $req= new Request(new TestInput('GET', '/?oauth_token=MISMATCHED-TOKEN&oauth_verifier=ABC'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth1Flow::SESSION_KEY, ['oauth_token' => 'REQUEST-TOKEN']);

    $fixture->authenticate($req, $res, $session);
  }

  #[@test]
  public function returns_session() {
    $access= ['oauth_token' => 'ACCESS-TOKEN', 'oauth_token_secret' => 'XYZ', 'access' => true];
    $fixture= new OAuth1Flow(self::AUTH, [self::ID, self::SECRET]);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth1Flow::SESSION_KEY, $access);

    $this->assertInstanceOf(Session::class, $fixture->authenticate($req, $res, $session));
  }
}