<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use test\{Assert, Expect, Test, Values};
use util\URI;
use web\auth\oauth\{Client, OAuth1Flow};
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;
use web\{Request, Response};

class OAuth1FlowTest extends FlowTest {
  use Clients;

  const SNS      = 'oauth1::flow';
  const AUTH     = 'https://example.com/oauth';
  const ID       = 'bf396750';
  const SECRET   = '5ebe2294ecd0e0f08eab7690d2a6ee69';
  const SERVICE  = 'https://service.example.com';
  const CALLBACK = 'https://service.example.com/callback';

  #[Test]
  public function can_create() {
    new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK);
  }

  #[Test]
  public function callback() {
    Assert::equals(new URI(self::CALLBACK), (new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK))->callback());
  }

  #[Test]
  public function calling() {
    Assert::equals(
      new URI('/test'),
      (new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK))->calling('/test')->callback()
    );
  }

  #[Test, Values(from: 'paths')]
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
    Assert::equals('http://localhost'.$path, current($session->value(self::SNS)['flow']));
  }

  #[Test, Values(from: 'fragments')]
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
    Assert::equals('http://localhost/#'.$fragment, current($session->value(self::SNS)['flow']));
  }

  #[Test]
  public function exchanges_request_token_for_access_token() {
    $access= ['oauth_token' => 'ACCESS-TOKEN', 'oauth_token_secret' => 'XYZ', 'access' => true];
    $fixture= newinstance(OAuth1Flow::class, [self::AUTH, [self::ID, self::SECRET], self::CALLBACK], [
      'request' => function($path, $token= null, $params= []) use($access) { return $access; }
    ]);
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['oauth_token' => 'REQUEST-TOKEN', 'target' => self::SERVICE]);

    $res= $this->authenticate($fixture, '/?oauth_token=REQUEST-TOKEN&oauth_verifier=ABC', $session);
    Assert::equals(self::SERVICE, $res->headers()['Location']);
    Assert::equals($access, $session->value(self::SNS)['token']);
  }

  #[Test, Expect(IllegalStateException::class)]
  public function raises_exception_on_state_mismatch() {
    $fixture= new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['oauth_token' => 'REQUEST-TOKEN', 'target' => self::SERVICE]);

    $this->authenticate($fixture, '/?oauth_token=MISMATCHED-TOKEN&oauth_verifier=ABC', $session);
  }

  #[Test]
  public function redirects_when_opened_with_server_state_and_freshly_created_session() {
    $request= ['oauth_token' => 'T'];
    $fixture= newinstance(OAuth1Flow::class, [self::AUTH, [self::ID, self::SECRET], self::CALLBACK], [
      'request' => function($path, $token= null, $params= []) use($request) { return $request; }
    ]);
    $session= (new ForTesting())->create();

    Assert::equals(
      sprintf('%s/authenticate?oauth_token=T&oauth_callback=%s', self::AUTH, urlencode(self::CALLBACK)),
      $this->redirectTo($this->authenticate($fixture, '/?oauth_token=REQUEST-TOKEN&oauth_verifier=ABC', $session))
    );
  }

  #[Test]
  public function returns_client() {
    $access= ['oauth_token' => 'ACCESS-TOKEN', 'oauth_token_secret' => 'XYZ', 'access' => true];
    $fixture= new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['token' => $access]);

    Assert::instance(Client::class, $fixture->authenticate($req, $res, $session));
  }

  #[Test]
  public function resets_state_after_returning_client() {
    $access= ['oauth_token' => 'ACCESS-TOKEN', 'oauth_token_secret' => 'XYZ', 'access' => true];
    $fixture= new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['token' => $access]);
    $fixture->authenticate($req, $res, $session);

    Assert::equals([], $session->value(self::SNS));
  }

  #[Test, Values(from: 'fragments')]
  public function appends_fragment($fragment) {
    $fixture= new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK);

    $req= new Request(new TestInput('GET', '/?oauth_token=SHARED_STATE&'.OAuth1Flow::FRAGMENT.'='.urlencode($fragment)));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['flow' => ['SHARED_STATE' => 'http://localhost/']]);

    $fixture->authenticate($req, $res, $session);

    Assert::equals('http://localhost/#'.$fragment, current($session->value(self::SNS)['flow']));
  }

  #[Test, Values(from: 'fragments')]
  public function replaces_fragment($fragment) {
    $fixture= new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK);

    $req= new Request(new TestInput('GET', '/?oauth_token=SHARED_STATE&'.OAuth1Flow::FRAGMENT.'='.urlencode($fragment)));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['flow' => ['SHARED_STATE' => 'http://localhost/#original']]);

    $fixture->authenticate($req, $res, $session);

    Assert::equals('http://localhost/#'.$fragment, current($session->value(self::SNS)['flow']));
  }

  /** @deprecated */
  #[Test, Values(from: 'paths')]
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

  #[Test]
  public function use_returned_client() {
    $flow= new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK);
    $fixture= $flow->userInfo();

    Assert::instance(
      Client::class,
      $fixture($this->responding(200, ['Content-Type' => 'application/json'], '{"id":"root"}'))
    );
  }

  #[Test]
  public function fetch_user_info() {
    $flow= new OAuth1Flow(self::AUTH, [self::ID, self::SECRET], self::CALLBACK);
    $fixture= $flow->fetchUser('http://example.com/graph/v1.0/me');

    Assert::equals(
      ['id' => 'root'],
      $fixture($this->responding(200, ['Content-Type' => 'application/json'], '{"id":"root"}'))
    );
  }

  #[Test, Values(['oauth::flow', 'flow'])]
  public function session_namespace($namespace) {
    $request= ['oauth_token' => 'T'];
    $fixture= newinstance(OAuth1Flow::class, [self::AUTH, [self::ID, self::SECRET], self::CALLBACK], [
      'request' => function($path, $token= null, $params= []) use($request) { return $request; }
    ]);
    $session= (new ForTesting())->create();
    $this->authenticate($fixture->namespaced($namespace), '/target', $session);

    Assert::equals('http://localhost/target', current($session->value($namespace)['flow']));
  }

  #[Test]
  public function parallel_requests_stored() {
    $fixture= newinstance(OAuth1Flow::class, [self::AUTH, [self::ID, self::SECRET], self::CALLBACK], [
      'request' => function($path, $token= null, $params= []) {
        static $i= 0;
        return ['oauth_token' => $i++];
      }
    ]);
    $session= (new ForTesting())->create();

    // Simulate parallel requests
    $this->authenticate($fixture, '/new', $session);
    $this->authenticate($fixture, '/favicon.ico', $session);

    Assert::equals(
      ['http://localhost/new',  'http://localhost/favicon.ico'],
      array_values($session->value(self::SNS)['flow'])
    );
  }
}