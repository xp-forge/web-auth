<?php namespace web\auth\oauth\unittest;

use unittest\TestCase;
use web\{Request, Response};
use web\auth\oauth\OAuth1Flow;
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;

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
}