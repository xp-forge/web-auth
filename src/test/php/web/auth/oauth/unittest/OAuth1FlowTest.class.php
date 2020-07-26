<?php namespace web\auth\oauth\unittest;

use unittest\TestCase;
use web\auth\oauth\{OAuth1Flow, Session};
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;
use web\{Request, Response};

class OAuth1FlowTest extends TestCase {
  const SERVICE = 'https://example.com/oauth';
  const ID      = 'bf396750';
  const SECRET  = '5ebe2294ecd0e0f08eab7690d2a6ee69';

  #[@test]
  public function can_create() {
    new OAuth1Flow(self::SERVICE, [self::ID, self::SECRET]);
  }

  #[@test]
  public function fetches_request_token_then_redirects_to_auth() {
    $fixture= newinstance(OAuth1Flow::class, [self::SERVICE, [self::ID, self::SECRET]], [
      'request' => function($path, $token= null, $params= []) {
        return ['oauth_token' => 'REQUEST-TOKEN'];
      }
    ]);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();

    $fixture->authenticate($req, $res, $session);

    $this->assertEquals(self::SERVICE.'/authenticate?oauth_token=REQUEST-TOKEN', $res->headers()['Location']);
  }

  #[@test]
  public function exchanges_request_token_for_access_token() {
    $access= ['oauth_token' => 'ACCESS-TOKEN', 'oauth_token_secret' => 'XYZ'];
    $fixture= newinstance(OAuth1Flow::class, [self::SERVICE, [self::ID, self::SECRET]], [
      'request' => function($path, $token= null, $params= []) use($access) { return $access; }
    ]);

    $req= new Request(new TestInput('GET', '/?oauth_token=REQUEST-TOKEN&oauth_verifier=ABC'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register('oauth.request', ['oauth_token' => 'REQUEST-TOKEN']);

    $fixture->authenticate($req, $res, $session);

    $this->assertEquals('http://localhost/', $res->headers()['Location']);
    $this->assertEquals($access, $session->value('oauth.access'));
  }

  #[@test]
  public function returns_session() {
    $access= ['oauth_token' => 'ACCESS-TOKEN', 'oauth_token_secret' => 'XYZ'];
    $fixture= new OAuth1Flow(self::SERVICE, [self::ID, self::SECRET]);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register('oauth.request', ['oauth_token' => 'REQUEST-TOKEN']);
    $session->register('oauth.access', $access);

    $this->assertInstanceOf(Session::class, $fixture->authenticate($req, $res, $session));
  }
}