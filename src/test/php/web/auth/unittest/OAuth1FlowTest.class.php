<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use unittest\Assert;
use unittest\{Expect, Test, TestCase};
use web\auth\oauth\{OAuth1Flow, Client};
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;
use web\{Request, Response};

class OAuth1FlowTest extends FlowTest {
  const AUTH     = 'https://example.com/oauth';
  const ID       = 'bf396750';
  const SECRET   = '5ebe2294ecd0e0f08eab7690d2a6ee69';
  const SERVICE  = 'https://service.example.com';
  const CALLBACK = 'https://service.example.com/callback';

  #[Test]
  public function can_create() {
    new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK);
  }

  #[Test, Values('paths')]
  public function fetches_request_token_then_redirects_to_auth($path) {
    $request= ['oauth_token' => 'T'];
    $fixture= newinstance(OAuth1Flow::class, [self::AUTH, [self::ID, self::SECRET], self::CALLBACK], [
      'request' => function($path, $token= null, $params= []) use($request) { return $request; }
    ]);
    $session= (new ForTesting())->create();

    Assert::equals(
      sprintf('%s/authenticate?oauth_token=T&oauth_callback=%s', self::AUTH, urlencode(self::CALLBACK)),
      $this->redirectTo($this->authenticate($fixture, $path, $session))
    );
    Assert::equals('http://localhost'.$path, $session->value(OAuth1Flow::SESSION_KEY)['target']);
  }

  #[Test, Values('fragments')]
  public function fetches_request_token_then_redirects_to_auth_with_fragment_in_special_parameter($fragment) {
    $request= ['oauth_token' => 'T'];
    $fixture= newinstance(OAuth1Flow::class, [self::AUTH, [self::ID, self::SECRET], self::CALLBACK], [
      'request' => function($path, $token= null, $params= []) use($request) { return $request; }
    ]);
    $session= (new ForTesting())->create();

    Assert::equals(
      sprintf('%s/authenticate?oauth_token=T&oauth_callback=%s', self::AUTH, urlencode(self::CALLBACK)),
      $this->redirectTo($this->authenticate($fixture, '/#'.$fragment, $session))
    );
    Assert::equals('http://localhost/#'.$fragment, $session->value(OAuth1Flow::SESSION_KEY)['target']);
  }

  #[Test]
  public function exchanges_request_token_for_access_token() {
    $access= ['oauth_token' => 'ACCESS-TOKEN', 'oauth_token_secret' => 'XYZ', 'access' => true];
    $fixture= newinstance(OAuth1Flow::class, [self::AUTH, [self::ID, self::SECRET], self::CALLBACK], [
      'request' => function($path, $token= null, $params= []) use($access) { return $access; }
    ]);
    $session= (new ForTesting())->create();
    $session->register(OAuth1Flow::SESSION_KEY, ['oauth_token' => 'REQUEST-TOKEN', 'target' => self::SERVICE]);

    $res= $this->authenticate($fixture, '/?oauth_token=REQUEST-TOKEN&oauth_verifier=ABC', $session);
    Assert::equals(self::SERVICE, $res->headers()['Location']);
    Assert::equals($access, $session->value(OAuth1Flow::SESSION_KEY));
  }

  #[Test, Expect(IllegalStateException::class)]
  public function raises_exception_on_state_mismatch() {
    $fixture= new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(OAuth1Flow::SESSION_KEY, ['oauth_token' => 'REQUEST-TOKEN', 'target' => self::SERVICE]);

    $this->authenticate($fixture, '/?oauth_token=MISMATCHED-TOKEN&oauth_verifier=ABC', $session);
  }

  #[Test]
  public function returns_client() {
    $access= ['oauth_token' => 'ACCESS-TOKEN', 'oauth_token_secret' => 'XYZ', 'access' => true];
    $fixture= new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth1Flow::SESSION_KEY, $access);

    Assert::instance(Client::class, $fixture->authenticate($req, $res, $session));
  }

  /** @deprecated */
  #[Test, Values('paths')]
  public function deprecated_usage_without_callback_uri($path) {
    $request= ['oauth_token' => 'T'];
    $fixture= newinstance(OAuth1Flow::class, [self::AUTH, [self::ID, self::SECRET]], [
      'request' => function($path, $token= null, $params= []) use($request) { return $request; }
    ]);
    \xp::gc();
    $session= (new ForTesting())->create();

    Assert::equals(
      sprintf('%s/authenticate?oauth_token=T&oauth_callback=%s', self::AUTH, urlencode('http://localhost'.$path)),
      $this->redirectTo($this->authenticate($fixture, $path, $session))
    );
  }
}