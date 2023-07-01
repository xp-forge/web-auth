<?php namespace web\auth\oauth;

use io\streams\Streams;
use lang\IllegalStateException;
use peer\http\HttpConnection;
use util\{Random, Secret, URI};
use web\auth\Flow;
use web\session\Sessions;

class OAuth2Flow extends Flow {
  const SESSION_KEY = 'oauth2::flow';

  private $auth, $tokens, $consumer, $scopes, $callback, $rand;

  /**
   * Creates a new OAuth 2 flow
   *
   * @param  string|util.URI $auth
   * @param  string|util.URI $tokens
   * @param  web.auth.oauth.Credentials|string[]|util.Secret[] $consumer
   * @param  string|util.URI $callback
   * @param  string[] $scopes
   */
  public function __construct($auth, $tokens, $consumer, $callback= null, $scopes= ['user']) {
    $this->auth= $auth instanceof URI ? $auth : new URI($auth);
    $this->tokens= $tokens instanceof URI ? $tokens : new URI($tokens);

    // BC: Support web.auth.oauth.Token instances
    if ($consumer instanceof Credentials) {
      $this->consumer= $consumer;
    } else if ($consumer instanceof Token) {
      $this->consumer= new BySecret($consumer->key()->reveal(), $consumer->secret());
    } else {
      $this->consumer= new BySecret(...$consumer);
    }

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

  /** @return ?util.URI */
  public function callback() { return $this->callback; }

  /** @return string[] */
  public function scopes() { return $this->scopes; }

  /**
   * Gets a token
   *
   * @param  [:string] $payload POST parameters
   * @return [:string] Token
   * @throws lang.IllegalStateException
   */
  protected function token($payload) {
    $c= new HttpConnection($this->tokens);
    $r= $c->post($payload, ['Accept' => 'application/x-www-form-urlencoded, application/json', 'User-Agent' => 'XP/OAuth2']);

    $body= Streams::readAll($r->in());
    if (200 !== $r->statusCode()) {
      throw new IllegalStateException('Cannot get access token (#'.$r->statusCode().'): '.$body);
    }

    $type= $r->header('Content-Type')[0];
    if (strstr($type, 'application/json')) {
      return json_decode($body, true);
    } else {
      parse_str($body, $token);
      return $token;
    }
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
    $result= $this->token($this->consumer->params($this->tokens) + [
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
    $stored= $session->value(self::SESSION_KEY);

    // We have an access token, reset state and return an authenticated session
    // See https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
    // and https://tools.ietf.org/html/rfc6749#section-5.1
    if (isset($stored['access_token'])) {
      $session->remove(self::SESSION_KEY);
      return new ByAccessToken(
        $stored['access_token'],
        $stored['token_type'] ?? 'Bearer',
        $stored['scope'] ?? null,
        $stored['expires_in'] ?? null,
        $stored['refresh_token'] ?? null,
        $stored['id_token'] ?? null
      );
    }

    $uri= $this->url(true)->resolve($request);
    $callback= $this->callback ? $uri->resolve($this->callback) : $this->service($uri);

    // Start authorization flow to acquire an access token
    $server= $request->param('state');
    if (null === $stored || null === $server) {

      // Reuse state
      if (isset($stored['state'])) {
        $state= $stored['state'];
      } else {
        $state= bin2hex($this->rand->bytes(16));
        $session->register(self::SESSION_KEY, ['state' => $state, 'target' => (string)$uri]);
        $session->transmit($response);
      }

      // Redirect the user to the authorization page
      $params= [
        'response_type' => 'code',
        'client_id'     => $this->consumer->clientId,
        'scope'         => implode(' ', $this->scopes),
        'redirect_uri'  => $callback,
        'state'         => $state
      ];
      $target= $this->auth->using()->params($params)->create();

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

    // Continue authorization flow
    $state= explode(self::FRAGMENT, $server);
    if ($state[0] === $stored['state']) {

      // Exchange the auth code for an access token
      $token= $this->token($this->consumer->params($this->tokens) + [
        'grant_type'    => 'authorization_code',
        'code'          => $request->param('code'),
        'redirect_uri'  => $callback,
        'state'         => $stored['state']
      ]);
      $session->register(self::SESSION_KEY, $token);
      $session->transmit($response);

      // Redirect to self, using encoded fragment if present
      $this->finalize($response, $stored['target'].(isset($state[1]) ? '#'.urldecode($state[1]) : ''));
      return null;
    }

    throw new IllegalStateException('Flow error, session state '.$stored['state'].' != server state '.$state[0]);
  }
}