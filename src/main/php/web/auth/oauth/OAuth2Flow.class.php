<?php namespace web\auth\oauth;

use io\streams\Streams;
use lang\IllegalStateException;
use peer\http\HttpConnection;
use util\{Random, Secret, URI};
use web\auth\Flow;
use web\session\Sessions;

class OAuth2Flow extends Flow {
  const SESSION_KEY = 'oauth2::flow';

  private $auth, $tokens, $consumer, $scopes, $rand;

  /**
   * Creates a new OAuth 2 flow
   *
   * @param  string|util.URI $auth
   * @param  string|util.URI $tokens
   * @param  web.auth.oauth.Token|string[]|util.Secret[] $consumer
   * @param  string[] $scopes
   */
  public function __construct($auth, $tokens, $consumer, $scopes= ['user']) {
    $this->auth= $auth instanceof URI ? $auth : new URI($auth);
    $this->tokens= $tokens instanceof URI ? $tokens : new URI($tokens);
    $this->consumer= $consumer instanceof Token ? $consumer : new Token(...$consumer);
    $this->scopes= $scopes;
    $this->rand= new Random();
  }

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
    // \util\cmd\Console::writeLine('>>> ', $payload);
    $c= new HttpConnection($this->tokens);
    $r= $c->post($payload, ['Accept' => 'application/x-www-form-urlencoded, application/json', 'User-Agent' => 'XP/OAuth2']);
    $body= Streams::readAll($r->in());
    // \util\cmd\Console::writeLine('<<< ', $body);

    if (200 !== $r->statusCode()) {
      throw new IllegalStateException('Cannot get access token (#'.$r->statusCode().'): '.$body);
    }

    $type= $r->header('Content-Type')[0];
    if (strstr($type, 'application/json')) {
      $token= json_decode($body, true);
    } else {
      parse_str($body, $token);
    }
    return $token;
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
    $state= $session->value(self::SESSION_KEY);

    // We have an access token, return an authenticated session
    if (isset($state['access_token'])) {
      return new ByAccessToken($state['access_token'], $state['token_type']);
    }

    // Start authorization flow to acquire an access token
    $uri= $this->url(true)->resolve($request);
    $server= $request->param('state');
    if (null === $state || null === $server) {
      $state= bin2hex($this->rand->bytes(16));
      $session->register(self::SESSION_KEY, $state);
      $session->transmit($response);

      // Redirect the user to the authorization page
      $target= $this->auth->using()->params([
        'response_type' => 'code',
        'client_id'     => $this->consumer->key()->reveal(),
        'scope'         => implode(' ', $this->scopes),
        'state'         => $state,
        'redirect_uri'  => $this->service($uri),
      ]);

      $this->login($response, $target->create());
      return null;
    } else if ($server === $state) {

      // Exchange the auth code for an access token
      $token= $this->token([
        'grant_type'    => 'authorization_code',
        'client_id'     => $this->consumer->key()->reveal(),
        'client_secret' => $this->consumer->secret()->reveal(),
        'code'          => $request->param('code'),
        'state'         => $state,
        'redirect_uri'  => $uri->using()->params([])->create(),
      ]);
      $session->register(self::SESSION_KEY, $token);
      $session->transmit($response);

      // Redirect to self, getting rid of OAuth request parameters
      $params= $request->params();
      unset($params['state'], $params['code'], $params['session_state']);
      $this->finalize($response, $uri->using()->params($params)->create());
      return null;
    }

    throw new IllegalStateException('Flow error, session state '.$state.' != server state '.$server);
  }
}