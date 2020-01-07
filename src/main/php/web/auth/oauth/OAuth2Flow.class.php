<?php namespace web\auth\oauth;

use io\streams\Streams;
use lang\IllegalStateException;
use peer\http\HttpConnection;
use util\Random;
use util\Secret;
use util\URI;
use web\auth\Flow;
use web\session\Sessions;

class OAuth2Flow implements Flow {
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
    $state= $session->value('oauth.state');
    if (null === $state) {
      $state= bin2hex($this->rand->bytes(16));
      $session->register('oauth.state', $state);

      // Redirect the user to the authorization page
      $target= $this->auth->using()->params([
        'response_type' => 'code',
        'client_id'     => $this->consumer->key()->reveal(),
        'redirect_uri'  => $request->uri(),
        'scope'         => implode(' ', $this->scopes),
        'state'         => $state,
      ]);
      $response->answer(302);
      $response->header('Location', $target->create());
      return null;
    } else if ($request->param('state') === $state) {

      // Exchange the auth code for an access token
      $token= $this->token([
        'grant_type'    => 'authorization_code',
        'client_id'     => $this->consumer->key()->reveal(),
        'client_secret' => $this->consumer->secret()->reveal(),
        'redirect_uri'  => $request->uri()->using()->params([])->create(),
        'code'          => $request->param('code'),
        'state'         => $state,
      ]);
      $session->register('oauth.token', $token);

      // Redirect to self, getting rid of "state" and "code" request parameters
      $response->answer(302);
      $response->header('Location', $request->uri()->using()->param('state', null)->param('code', null)->create());
      return null;
    } else if ($token= $session->value('oauth.token')) {

      // Finally, return an authenticated session
      return new ByAccessToken($token['access_token'], $token['token_type']);
    }
    
    throw new IllegalStateException('Flow error, session '.$state.' != request '.$request->param('state'));
  }
}