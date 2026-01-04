<?php namespace web\auth\oauth;

use io\streams\Streams;
use lang\IllegalStateException;
use peer\http\HttpConnection;
use util\{Random, Secret, URI};
use web\session\Sessions;

/** @test web.auth.unittest.OAuth2FlowTest */
class OAuth2Flow extends OAuthFlow {
  private $auth, $backend, $scopes, $rand;

  /**
   * Creates a new OAuth 2 flow
   *
   * @param  string|util.URI $auth
   * @param  string|util.URI|web.auth.oauth.OAuth2Endpoint $tokens
   * @param  ?web.auth.oauth.Credentials|(string|util.Secret)[] $consumer
   * @param  string|util.URI $callback
   * @param  string[] $scopes
   */
  public function __construct($auth, $tokens, $consumer, $callback= null, $scopes= ['user']) {
    $this->namespace= 'oauth2::flow';
    $this->auth= $auth instanceof URI ? $auth : new URI($auth);
    $this->backend= $tokens instanceof OAuth2Endpoint
      ? $tokens->using($consumer)
      : new OAuth2Endpoint($tokens, $consumer)
    ;

    // BC: Support deprecated constructor signature without callback
    if (is_array($callback) || null === $callback) {
      trigger_error('Missing parameter $callback', E_USER_DEPRECATED);
      $this->callback= null;
      $this->scopes= $callback ?? $scopes;
    } else {
      $this->callback= $callback instanceof URI ? $callback : new URI($callback);
      $this->scopes= $scopes;
    }

    $this->rand= new Random();
  }

  /** @return string[] */
  public function scopes() { return $this->scopes; }

  /** @param string[] $scopes */
  public function requesting($scopes): self {
    $this->scopes= $scopes;
    return $this;
  }

  /**
   * Refreshes access token given a refresh token if necessary.
   *
   * @param  [:var] $claims
   * @return ?web.auth.Authorization
   * @throws lang.IllegalStateException
   */
  public function refresh(array $claims) {
    if (time() < $claims['expires']) return null;

    // Refresh token
    $result= $this->backend->acquire([
      'grant_type'    => 'refresh_token',
      'refresh_token' => $claims['refresh'],
    ]);
    return new ByAccessToken(
      $result['access_token'],
      $result['token_type'] ?? 'Bearer',
      $result['scope'] ?? null,
      $result['expires_in'] ?? null,
      $result['refresh_token'] ?? null,
      $result['id_token'] ?? null
    );
  }

  /**
   * Executes authentication flow, returning the authentication result
   *
   * @param  web.Request $request
   * @param  web.Response $response
   * @param  web.session.Session $session
   * @return ?web.auth.Authorization
   * @throws lang.IllegalStateException
   */
  public function authenticate($request, $response, $session) {
    $stored= $session->value($this->namespace);

    // We have an access token, reset state and return an authenticated session
    // See https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
    // and https://tools.ietf.org/html/rfc6749#section-5.1
    if ($token= $stored['token'] ?? null) {
      unset($stored['token']);
      $session->register($this->namespace, $stored);

      return new ByAccessToken(
        $token['access_token'],
        $token['token_type'] ?? 'Bearer',
        $token['scope'] ?? null,
        $token['expires_in'] ?? null,
        $token['refresh_token'] ?? null,
        $token['id_token'] ?? null
      );
    }

    $uri= $this->url(true)->resolve($request);
    $callback= $this->callback ? $uri->resolve($this->callback) : $this->service($uri);

    // Start authorization flow to acquire an access token
    $server= $request->param('state');
    if (null === $server || null === $stored) {
      $state= bin2hex($this->rand->bytes(16));
      $seed= $this->backend->seed();

      $stored??= ['flow' => []];
      $stored['flow'][$state]= ['uri' => (string)$uri, 'seed' => $seed];
      $session->register($this->namespace, $stored);
      $session->transmit($response);

      // Redirect the user to the authorization page
      $params= [
        'response_type' => 'code',
        'client_id'     => $this->backend->clientId(),
        'scope'         => implode(' ', $this->scopes),
        'redirect_uri'  => $callback,
        'state'         => $state,
      ];
      $target= $this->auth->using()->params($this->backend->pass($params, $seed))->create();

      // If a URL fragment is present, append it to the state parameter, which
      // is passed as the last parameter to the authentication service.
      $this->redirect($response, $target, sprintf('
        var target = "%1$s";
        var hash = document.location.hash.substring(1);

        if (hash) {
          document.location.replace(target + "%2$s" + encodeURIComponent(hash));
        } else {
          document.location.replace(target);
        }',
        $target,
        self::FRAGMENT
      ));
      return null;
    }

    // Continue authorization flow, handling previous session layout
    $state= explode(self::FRAGMENT, $server);
    if (
      ($target= $stored['flow'][$state[0]] ?? null) ||
      (($target= $stored['target'] ?? null) && ($state[0] === $stored['state']))
    ) {
      unset($stored['flow'][$state[0]]);

      // Target is an array for old session layout and during transition
      if (is_array($target)) {
        $uri= $target['uri'];
        $seed= $target['seed'];
      } else {
        $uri= $target;
        $seed= [];
      }

      // Exchange the auth code for an access token
      $params= [
        'grant_type'    => 'authorization_code',
        'code'          => $request->param('code'),
        'redirect_uri'  => $callback,
        'state'         => $server
      ];
      $stored['token']= $this->backend->acquire($params, $seed);
      $session->register($this->namespace, $stored);
      $session->transmit($response);

      // Redirect to self, using encoded fragment if present
      $this->finalize($response, $uri.(isset($state[1]) ? '#'.urldecode($state[1]) : ''));
      return null;
    }

    throw new IllegalStateException(sprintf(
      'Flow error, unknown server state %s expecting one of %s',
      $state[0],
      implode(', ', array_keys($stored['flow'] ?? [$stored['state'] => true]))
    ));
  }
}