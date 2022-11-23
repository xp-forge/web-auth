<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use unittest\{Assert, Expect, Test, TestCase, Values};
use util\URI;
use web\auth\oauth\{OAuth2Flow, Client};
use web\auth\{UseCallback, UseRequest, UseURL};
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;
use web\{Request, Response};

class OAuth2FlowTest extends FlowTest {
  const AUTH     = 'https://example.com/oauth/authorize';
  const TOKENS   = 'https://example.com/oauth/access_token';
  const CONSUMER = ['bf396750', '5ebe2294ecd0e0f08eab7690d2a6ee69'];
  const SERVICE  = 'https://service.example.com';
  const CALLBACK = 'https://service.example.com/callback';

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
      $session->value(OAuth2Flow::SESSION_KEY)['state']
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
  public function scopes() {
    $scopes= ['user', 'profile'];
    Assert::equals($scopes, (new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK, $scopes))->scopes());
  }

  #[Test]
  public function scopes_defaults_to_user() {
    Assert::equals(['user'], (new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK))->scopes());
  }

  #[Test, Values('paths')]
  public function redirects_to_auth($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture, $path, $session),
      $session
    );
    Assert::equals('http://localhost'.$path, $session->value(OAuth2Flow::SESSION_KEY)['target']);
  }

  #[Test, Values('paths')]
  public function redirects_to_auth_with_relative_callback($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, '/callback');
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      'http://localhost/callback',
      $fixture->scopes(),
      $this->authenticate($fixture, $path, $session),
      $session
    );
    Assert::equals('http://localhost'.$path, $session->value(OAuth2Flow::SESSION_KEY)['target']);
  }

  #[Test, Values('paths')]
  public function redirects_to_auth_using_request($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture->target(new UseRequest()), $path, $session),
      $session
    );
    Assert::equals('http://localhost'.$path, $session->value(OAuth2Flow::SESSION_KEY)['target']);
  }

  #[Test, Values('paths')]
  public function redirects_to_auth_using_url($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture->target(new UseURL(self::SERVICE)), $path, $session),
      $session
    );
    Assert::equals(self::SERVICE.$path, $session->value(OAuth2Flow::SESSION_KEY)['target']);
  }

  #[Test, Values('fragments')]
  public function redirects_to_sso_with_fragment($fragment) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture, '/#'.$fragment, $session),
      $session
    );
    Assert::equals('http://localhost/#'.$fragment, $session->value(OAuth2Flow::SESSION_KEY)['target']);
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
    $session->register(OAuth2Flow::SESSION_KEY, ['state' => 'PREVIOUS_STATE', 'target' => self::SERVICE]);

    $this->assertLoginWith(
      self::CALLBACK,
      $fixture->scopes(),
      $this->authenticate($fixture, '/', $session),
      $session
    );
  }

  #[Test]
  public function reuses_state_when_previous_redirect_incomplete() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, ['state' => 'REUSED_STATE', 'target' => self::SERVICE]);

    $this->authenticate($fixture, '/', $session);
    Assert::equals('REUSED_STATE', $session->value(OAuth2Flow::SESSION_KEY)['state']);
  }

  #[Test]
  public function gets_access_token_and_redirects_to_self() {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $state= 'SHAREDSTATE';
    $fixture= newinstance(OAuth2Flow::class, [self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK], [
      'token' => function($payload) use($token) { return $token; }
    ]);
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, ['state' => $state, 'target' => self::SERVICE]);

    $res= $this->authenticate($fixture, '/?code=SERVER_CODE&state='.$state, $session);
    Assert::equals(self::SERVICE, $res->headers()['Location']);
    Assert::equals($token, $session->value(OAuth2Flow::SESSION_KEY));
  }

  #[Test, Values('fragments')]
  public function gets_access_token_and_redirects_to_self_with_fragment($fragment) {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $state= 'SHAREDSTATE';
    $fixture= newinstance(OAuth2Flow::class, [self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK], [
      'token' => function($payload) use($token) { return $token; }
    ]);
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, ['state' => $state, 'target' => self::SERVICE]);

    $res= $this->authenticate($fixture, '/?code=SERVER_CODE&state='.$state.OAuth2Flow::FRAGMENT.urlencode($fragment), $session);
    Assert::equals(self::SERVICE.'#'.$fragment, $res->headers()['Location']);
    Assert::equals($token, $session->value(OAuth2Flow::SESSION_KEY));
  }

  #[Test, Expect(IllegalStateException::class)]
  public function raises_exception_on_state_mismatch() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, ['state' => 'CLIENTSTATE', 'target' => self::SERVICE]);

    $this->authenticate($fixture, '/?state=SERVERSTATE&code=SERVER_CODE', $session);
  }

  #[Test, Values([[['access_token' => '<TOKEN>', 'token_type' => 'Bearer']], [['access_token' => '<TOKEN>']]])]
  public function returns_client_in_final_step($response) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, $response);

    Assert::instance(Client::class, $fixture->authenticate($req, $res, $session));
  }

  #[Test]
  public function resets_state_after_returning_client() {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, $token);
    $fixture->authenticate($req, $res, $session);

    Assert::null($session->value(OAuth2Flow::SESSION_KEY));
  }

  #[Test]
  public function claims_returned() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, ['access_token' => '<T>']);

    Assert::null($fixture->authenticate($req, $res, $session)->claims());
  }

  #[Test]
  public function claims_returned_with_expiry() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, self::CALLBACK);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, ['access_token' => '<T>', 'expires_in' => 3600, 'refresh_token' => '<R>']);

    Assert::equals(
      ['expires' => time() + 3600, 'refresh' => '<R>'],
      $fixture->authenticate($req, $res, $session)->claims()
    );
  }

  /** @deprecated */
  #[Test, Values('paths')]
  public function deprecated_usage_without_callback_uri($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER);
    \xp::gc();

    $session= (new ForTesting())->create();
    $this->assertLoginWith(
      'http://localhost'.$path,
      $fixture->scopes(),
      $this->authenticate($fixture, $path, $session),
      $session
    );
  }

  /** @deprecated */
  #[Test, Values('paths')]
  public function deprecated_usage_with_scopes_in_place_of_callback_uri($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, ['user']);
    \xp::gc();

    $session= (new ForTesting())->create();
    $this->assertLoginWith(
      'http://localhost'.$path,
      $fixture->scopes(),
      $this->authenticate($fixture, $path, $session),
      $session
    );
  }
}