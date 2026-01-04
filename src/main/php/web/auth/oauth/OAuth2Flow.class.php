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
    return ByAccessToken::from($this->backend->acquire([
      'grant_type'    => 'refresh_token',
      'refresh_token' => $claims['refresh'],
    ]));
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
    $stored= $session->value($this->namespace) ?? ['state' => []];

    // We have an access token, remove and return an authenticated session. The
    // authentication implementation registers the user and transmits the session.
    if ($token= $stored['token'] ?? null) {
      unset($stored['token']);
      $session->register($this->namespace, $stored);

      return ByAccessToken::from($token);
    }

    // Enter authentication flow, resolving callback URI against the curren request.
    $uri= $this->url(true)->resolve($request);
    $callback= $this->callback ? $uri->resolve($this->callback) : $this->service($uri);

    // Check whether we are continuing an existing authentication flow based on the
    // state given by the server and our session; or if we need to start a new one.
    if (null === ($server= $request->param('state'))) {
      $flow= null;
    } else {
      sscanf($server, self::STATE, $state, $fragment);
      $flow= $this->flow($state, $stored);
    }

    if (null === $flow) {
      $state= bin2hex($this->rand->bytes(16));
      $seed= $this->backend->seed();

      $stored['flows'][$state]= ['uri' => (string)$uri, 'seed' => $seed];
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
      // is always passed as the last parameter to the authentication service.
      $separator= self::FRAGMENT;
      return $this->redirect($response, $target, <<<JS
        var hash = document.location.hash;
        if (hash) {
          document.location.replace('{$target}{$separator}' + encodeURIComponent(hash.substring(1)));
        } else {
          document.location.replace('{$target}');
        }
        JS
      );
    } else {

      // Exchange the auth code for an access token, then remove the stored state.
      $params= [
        'grant_type'    => 'authorization_code',
        'code'          => $request->param('code'),
        'redirect_uri'  => $callback,
        'state'         => $state
      ];
      $stored['token']= $this->backend->acquire($params, $flow['seed']);

      unset($stored['flows'][$state], $stored['flow'][$state]);
      $session->register($this->namespace, $stored);
      $session->transmit($response);

      // Redirect to self, using encoded fragment if present
      return $this->finalize($response, $flow['uri'].(isset($fragment) ? '#'.urldecode($fragment) : ''));
    }
  }
}