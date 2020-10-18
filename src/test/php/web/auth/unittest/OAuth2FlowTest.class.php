<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use unittest\Assert;
use unittest\{Expect, Test, TestCase, Values};
use web\auth\oauth\{OAuth2Flow, Client};
use web\auth\{UseRequest, UseURL};
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;
use web\{Request, Response};

class OAuth2FlowTest extends FlowTest {
  const AUTH     = 'https://example.com/oauth/authorize';
  const TOKENS   = 'https://example.com/oauth/access_token';
  const CONSUMER = ['bf396750', '5ebe2294ecd0e0f08eab7690d2a6ee69'];
  const SERVICE  = 'https://service.example.com';

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
      '%s?response_type=code&client_id=%s&scope=%s&state=%s&redirect_uri=%s',
      self::AUTH,
      self::CONSUMER[0],
      implode('+', $scope),
      $session->value(OAuth2Flow::SESSION_KEY),
      urlencode($service)
    );
    Assert::equals($url, $this->redirectTo($res));
  }

  #[Test]
  public function can_create() {
    new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER);
  }

  #[Test]
  public function default_scopes() {
    Assert::equals(['user'], (new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER))->scopes());
  }

  #[Test, Values('paths')]
  public function redirects_to_auth($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      'http://localhost'.$path,
      $fixture->scopes(),
      $this->authenticate($fixture, $path, $session),
      $session
    );
  }

  #[Test, Values('paths')]
  public function redirects_to_auth_using_request($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      'http://localhost'.$path,
      $fixture->scopes(),
      $this->authenticate($fixture->target(new UseRequest()), $path, $session),
      $session
    );
  }

  #[Test, Values('paths')]
  public function redirects_to_auth_using_url($path) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      self::SERVICE.$path,
      $fixture->scopes(),
      $this->authenticate($fixture->target(new UseURL(self::SERVICE)), $path, $session),
      $session
    );
  }

  #[Test, Values('fragments')]
  public function redirects_to_sso_with_fragment_in_special_parameter($fragment) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      'http://localhost/?_='.urlencode($fragment),
      $fixture->scopes(),
      $this->authenticate($fixture, '/#'.$fragment, $session),
      $session
    );
  }

  #[Test, Values([[['user']], [['user', 'openid']]])]
  public function redirects_to_auth_and_passes_scope($scopes) {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER, $scopes);
    $session= (new ForTesting())->create();

    $this->assertLoginWith(
      'http://localhost/',
      $scopes,
      $this->authenticate($fixture, '/', $session),
      $session
    );
  }

  #[Test]
  public function redirects_to_auth_when_previous_redirect_incomplete() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER);
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, 'PREVIOUS_STATE');

    $this->assertLoginWith(
      'http://localhost/',
      $fixture->scopes(),
      $this->authenticate($fixture, '/', $session),
      $session
    );
  }

  #[Test]
  public function gets_access_token_and_redirects_to_self() {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $state= 'SHARED_STATE';
    $fixture= newinstance(OAuth2Flow::class, [self::AUTH, self::TOKENS, self::CONSUMER], [
      'token' => function($payload) use($token) { return $token; }
    ]);
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, $state);

    $res= $this->authenticate($fixture, '/?state='.$state.'&code=SERVER_CODE', $session);
    Assert::equals('http://localhost/', $res->headers()['Location']);
    Assert::equals($token, $session->value(OAuth2Flow::SESSION_KEY));
  }

  #[Test, Values('fragments')]
  public function gets_access_token_and_redirects_to_self_with_fragment($fragment) {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $state= 'SHARED_STATE';
    $fixture= newinstance(OAuth2Flow::class, [self::AUTH, self::TOKENS, self::CONSUMER], [
      'token' => function($payload) use($token) { return $token; }
    ]);
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, $state);

    $res= $this->authenticate($fixture, '/?state='.$state.'&code=SERVER_CODE&_='.urlencode($fragment), $session);
    Assert::equals('http://localhost/#'.$fragment, $res->headers()['Location']);
    Assert::equals($token, $session->value(OAuth2Flow::SESSION_KEY));
  }

  #[Test, Expect(IllegalStateException::class)]
  public function raises_exception_on_state_mismatch() {
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER);
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, 'CLIENT_STATE');

    $this->authenticate($fixture, '/?state=SERVER_STATE&code=SERVER_CODE', $session);
  }

  #[Test]
  public function returns_client_in_final_step() {
    $token= ['access_token' => '<TOKEN>', 'token_type' => 'Bearer'];
    $fixture= new OAuth2Flow(self::AUTH, self::TOKENS, self::CONSUMER);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $session= (new ForTesting())->create();
    $session->register(OAuth2Flow::SESSION_KEY, $token);

    Assert::instance(Client::class, $fixture->authenticate($req, $res, $session));
  }
}