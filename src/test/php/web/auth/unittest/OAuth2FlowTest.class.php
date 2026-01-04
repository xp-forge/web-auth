<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use test\verify\Runtime;
use test\{Assert, Expect, Test, TestCase, Values};
use util\URI;
use web\auth\oauth\{Client, BySecret, ByCertificate, Token, OAuth2Flow, OAuth2Endpoint};
use web\auth\{UseCallback, UseRequest, UseURL};
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;
use web\{Request, Response};

class OAuth2FlowTest extends FlowTest {
  use PrivateKey, Clients;

  const SNS         = 'oauth2::flow';
  const AUTH        = 'https://example.com/oauth/authorize';
  const TOKENS      = 'https://example.com/oauth/access_token';
  const CONSUMER    = ['bf396750', '5ebe2294ecd0e0f08eab7690d2a6ee69'];
  const SERVICE     = 'https://service.example.com';
  const CALLBACK    = 'https://service.example.com/callback';
  const FINGERPRINT = 'd41d8cd98f00b204e9800998ecf8427e';

  /**
   * Asserts a given response redirects to a given OAuth endpoint
   *
   * @param  string $service
   * @param  string[] $scope
   * @param  web.Response $res
   * @param  web.session.ISession $session
   * @throws unittest.AssertionFailedError
   */
  private function assertLoginWith($service, $scope, $res, $session) {
    $url= sprintf(
      '%s?response_type=code&client_id=%s&scope=%s&redirect_uri=%s&state=%s',
      self::AUTH,
      self::CONSUMER[0],
      implode('+', $scope),
      urlencode($service),
      array_key_last($session->value(self::SNS)['flows'])
    );
    Assert::equals($url, $this->redirectTo($res));
  }

  #[Test]
  public function can_create() {
    new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
  }

  #[Test]
  public function callback() {
    Assert::equals(new URI(self::CALLBACK), (new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK))->callback());
  }

  #[Test]
  public function calling() {
    Assert::equals(
      new URI('/test'),
      (new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK))->calling('/test')->callback()
    );
  }

  #[Test]
  public function scopes() {
    $scopes= ['user', 'profile'];
    Assert::equals($scopes, (new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK, $scopes))->scopes());
  }

  #[Test]
  public function requesting_scopes() {
    $scopes= ['user', 'profile'];
    Assert::equals(
      $scopes,
      (new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK))->requesting($scopes)->scopes()
    );
  }

  #[Test]
  public function scopes_defaults_to_user() {
    Assert::equals(['user'], (new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK))->scopes());
  }

  #[Test, Values(from: 'paths')]
  public function redirects_to_auth($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture, $path, $session),
      $session
    );
    Assert::equals(['uri' => 'http://localhost'.$path, 'seed' => []], current($session->value(self::SNS)['flows']));
  }

  #[Test, Values(from: 'paths')]
  public function redirects_to_auth_with_relative_callback($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, '/callback');
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      'http://localhost/callback',
      $fixture->scopes(),
      $this->authenticate($fixture, $path, $session),
      $session
    );
    Assert::equals(['uri' => 'http://localhost'.$path, 'seed' => []], current($session->value(self::SNS)['flows']));
  }

  #[Test, Values(from: 'paths')]
  public function redirects_to_auth_using_request($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture->target(new UseRequest()), $path, $session),
      $session
    );
    Assert::equals(['uri' => 'http://localhost'.$path, 'seed' => []], current($session->value(self::SNS)['flows']));
  }

  #[Test, Values(from: 'paths')]
  public function redirects_to_auth_using_url($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture->target(new UseURL(self::SERVICE)), $path, $session),
      $session
    );
    Assert::equals(['uri' => self::SERVICE.$path, 'seed' => []], current($session->value(self::SNS)['flows']));
  }

  #[Test, Values(from: 'fragments')]
  public function redirects_to_sso_with_fragment($fragment) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture, '/#'.$fragment, $session),
      $session
    );
    Assert::equals(['uri' => 'http://localhost/#'.$fragment, 'seed' => []], current($session->value(self::SNS)['flows']));
  }

  #[Test, Values([[['user']], [['user', 'openid']]])]
  public function redirects_to_auth_and_passes_scope($scopes) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK, $scopes);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      self::CALLBACK,
      $scopes,
      $this->authenticate($fixture, '/', $session),
      $session
    );
  }

  #[Test]
  public function redirects_to_auth_when_previous_redirect_incomplete() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['flows' => ['PREVIOUS_STATE' => ['uri' => self::SERVICE, 'seed' => []]]]);

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture, '/', $session),
      $session
    );
  }

  #[Test]
  public function does_not_reuse_state_when_previous_redirect_incomplete() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['flows' => ['PREVIOUS_STATE' => ['uri' => self::SERVICE, 'seed' => []]]]);

    $this->authenticate($fixture, '/new', $session);
    Assert::notEquals('PREVIOUS_STATE', array_key_last($session->value(self::SNS)['flows']));
  }

  #[Test]
  public function passes_client_id_and_secret() {
    $credentials= new BySecret('client-id', 'secret');
    $state= 'SHAREDSTATE';
    $tokens= newinstance(OAuth2Endpoint::class, [self::TOKENS], [
      'request' => function($payload) use(&$passed) { $passed= $payload; /* Not implemented */ }
    ]);
    $fixture= new OAuth2Flow(self::AUTH, $tokens, $credentials, self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['flows' => [$state => ['uri' => self::SERVICE, 'seed' => []]]]);

    $this->authenticate($fixture, '/?code=SERVER_CODE&state='.$state, $session);
    Assert::equals('authorization_code', $passed['grant_type']);
    Assert::equals('SERVER_CODE', $passed['code']);
    Assert::equals('client-id', $passed['client_id']);
    Assert::equals('secret', $passed['client_secret']);
  }

  #[Test, Runtime(extensions: ['openssl'])]
  public function passes_client_id_assertion_and_rs256_jwt() {
    $credentials= new ByCertificate('client-id', self::FINGERPRINT, $this->newPrivateKey());
    $state= 'SHAREDSTATE';
    $tokens= newinstance(OAuth2Endpoint::class, [self::TOKENS], [
      'request' => function($payload) use(&$passed) { $passed= $payload; /* Not implemented */ }
    ]);
    $fixture= new OAuth2Flow(self::AUTH, $tokens, $credentials, self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['flows' => [$state => ['uri' => self::SERVICE, 'seed' => []]]]);

    $this->authenticate($fixture, '/?code=SERVER_CODE&state='.$state, $session);
    Assert::equals('authorization_code', $passed['grant_type']);
    Assert::equals('SERVER_CODE', $passed['code']);
    Assert::equals('client-id', $passed['client_id']);
    Assert::equals('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $passed['client_assertion_type']);
    Assert::true(isset($passed['client_assertion']));
  }

  #[Test]
  public function gets_access_token_and_redirects_to_self() {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $state= 'SHAREDSTATE';
    $tokens= newinstance(OAuth2Endpoint::class, [self::TOKENS], [
      'request' => function($payload) use($token) { return $token; }
    ]);
    $fixture= new OAuth2Flow(self::AUTH, $tokens, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['flows' => [$state => ['uri' => self::SERVICE, 'seed' => []]]]);

    $res= $this->authenticate($fixture, '/?code=SERVER_CODE&state='.$state, $session);
    Assert::equals(self::SERVICE, $res->headers()['Location']);
    Assert::equals($token, $session->value(self::SNS)['token']);
  }

  /** @deprecated */
  #[Test]
  public function gets_access_token_using_target_session_layout() {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $state= 'SHAREDSTATE';
    $tokens= newinstance(OAuth2Endpoint::class, [self::TOKENS], [
      'request' => function($payload) use($token) { return $token; }
    ]);
    $fixture= new OAuth2Flow(self::AUTH, $tokens, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['state' => $state, 'target' => self::SERVICE]);

    $res= $this->authenticate($fixture, '/?code=SERVER_CODE&state='.$state, $session);
    Assert::equals(self::SERVICE, $res->headers()['Location']);
    Assert::equals($token, $session->value(self::SNS)['token']);
  }

  /** @deprecated */
  #[Test]
  public function gets_access_token_using_flow_service_session_layout() {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $state= 'SHAREDSTATE';
    $tokens= newinstance(OAuth2Endpoint::class, [self::TOKENS], [
      'request' => function($payload) use($token) { return $token; }
    ]);
    $fixture= new OAuth2Flow(self::AUTH, $tokens, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['flow' => [$state => self::SERVICE]]);

    $res= $this->authenticate($fixture, '/?code=SERVER_CODE&state='.$state, $session);
    Assert::equals(self::SERVICE, $res->headers()['Location']);
    Assert::equals($token, $session->value(self::SNS)['token']);
  }


  #[Test, Values(from: 'fragments')]
  public function gets_access_token_and_redirects_to_self_with_fragment($fragment) {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $state= 'SHAREDSTATE';
    $tokens= newinstance(OAuth2Endpoint::class, [self::TOKENS], [
      'request' => function($payload) use($token) { return $token; }
    ]);
    $fixture= new OAuth2Flow(self::AUTH, $tokens, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['flows' => [$state => ['uri' => self::SERVICE, 'seed' => []]]]);

    $res= $this->authenticate($fixture, '/?code=SERVER_CODE&state='.$state.OAuth2Flow::FRAGMENT.urlencode($fragment), $session);
    Assert::equals(self::SERVICE.'#'.$fragment, $res->headers()['Location']);
    Assert::equals($token, $session->value(self::SNS)['token']);
  }

  #[Test]
  public function redirects_when_opened_with_server_state_and_previous_flow() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['flows' => ['PREVIOUS_STATE' => ['uri' => self::SERVICE, 'seed' => []]]]);

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture, '/?state=SERVERSTATE&code=SERVER_CODE', $session),
      $session
    );
  }

  #[Test]
  public function redirects_when_opened_with_server_state_and_freshly_created_session() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture, '/?state=SERVERSTATE&code=SERVER_CODE', $session),
      $session
    );
  }

  #[Test, Values([[['access_token' => '<TOKEN>', 'token_type' => 'Bearer']], [['access_token' => '<TOKEN>']]])]
  public function returns_client_in_final_step($token) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['token' => $token]);

    Assert::instance(Client::class, $fixture->authenticate($req, $res, $session));
  }

  #[Test]
  public function removes_token_after_returning_it() {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['token' => $token]);
    $fixture->authenticate($req, $res, $session);

    Assert::equals([], $session->value(self::SNS));
  }

  #[Test]
  public function claims_returned() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['token' => ['access_token' => '<T>']]);

    Assert::null($fixture->authenticate($req, $res, $session)->claims());
  }

  #[Test]
  public function claims_returned_with_expiry() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(self::SNS, ['token' => [
      'access_token'  => '<T>',
      'expires_in'    => 3600,
      'refresh_token' => '<R>'
    ]]);

    Assert::equals(
      ['expires' => time() + 3600, 'refresh' => '<R>'],
      $fixture->authenticate($req, $res, $session)->claims()
    );
  }

  #[Test]
  public function use_returned_client() {
    $flow= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $fixture= $flow->userInfo();

    Assert::instance(
      Client::class,
      $fixture($this->responding(200, ['Content-Type' => 'application/json'], '{"id":"root"}'))
    );
  }

  #[Test]
  public function fetch_user_info() {
    $flow= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $fixture= $flow->fetchUser('http://example.com/graph/v1.0/me');

    Assert::equals(
      ['id' => 'root'],
      $fixture($this->responding(200, ['Content-Type' => 'application/json'], '{"id":"root"}'))
    );
  }

  #[Test]
  public function parallel_requests_stored() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();

    // Simulate parallel requests
    $this->authenticate($fixture, '/new', $session);
    $this->authenticate($fixture, '/favicon.ico', $session);

    Assert::equals(
      [
        ['uri' => 'http://localhost/new', 'seed' => []],
        ['uri' => 'http://localhost/favicon.ico', 'seed' => []],
      ],
      array_values($session->value(self::SNS)['flows'])
    );
  }
}