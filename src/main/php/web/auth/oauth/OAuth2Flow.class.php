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
   * @param  web.auth.oauth.Token|string[]|util.Secret[] $consumer
   * @param  string|util.URI $callback
   * @param  string[] $scopes
   */
  public function __construct($auth, $tokens, $consumer, $callback= null, $scopes= ['user']) {
    $this->auth= $auth instanceof URI ? $auth : new URI($auth);
    $this->tokens= $tokens instanceof URI ? $tokens : new URI($tokens);
    $this->consumer= $consumer instanceof Token ? $consumer : new Token(...$consumer);

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
   * Executes authentication flow, returning the authentication result
   *
   * @param  web.Request $request
   * @param  web.Response $response
   * @param  web.session.Session $session
   * @return var
   * @throws lang.IllegalStateException
   */
  public function authenticate($request, $response, $session) {
    $stored= $session->value(self::SESSION_KEY);

    // We have an access token, return an authenticated session
    if (isset($stored['access_token'])) {
      return new ByAccessToken($stored['access_token'], $stored['token_type']);
    }

    $uri= $this->url(true)->resolve($request);
    $callback= $this->callback ? $uri->resolve($this->callback) : $this->service($uri);

    // Start authorization flow to acquire an access token
    $server= $request->param('state');
    if (null === $stored || null === $server) {
      $state= bin2hex($this->rand->bytes(16));
      $session->register(self::SESSION_KEY, ['state' => $state, 'target' => (string)$uri]);
      $session->transmit($response);

      // Redirect the user to the authorization page
      $target= $this->auth->using()->params([
        'response_type' => 'code',
        'client_id'     => $this->consumer->key()->reveal(),
        'scope'         => implode(' ', $this->scopes),
        'redirect_uri'  => $callback,
        'state'         => $state,
      ]);

      $this->login($response, $target->create());
      return null;
    }

    // Continue authorization flow
    $state= explode('?', $server);
    if ($state[0] === $stored['state']) {

      // Exchange the auth code for an access token
      $token= $this->token([
        'grant_type'    => 'authorization_code',
        'client_id'     => $this->consumer->key()->reveal(),
        'client_secret' => $this->consumer->secret()->reveal(),
        'code'          => $request->param('code'),
        'redirect_uri'  => $callback,
        'state'         => $stored['state'],
      ]);
      $session->register(self::SESSION_KEY, $token);
      $session->transmit($response);

      // Redirect to self, using encoded fragment parameter if present
      $this->finalize($response, $stored['target'].(isset($state[1])
        ? '#'.urldecode(substr($state[1], strlen(self::FRAGMENT) + 1))
        : ''
      ));
      return null;
    }

    throw new IllegalStateException('Flow error, session state '.$stored['state'].' != server state '.$state[0]);
  }
}