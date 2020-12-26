<?php namespace web\auth\oauth;

use io\streams\Streams;
use lang\IllegalStateException;
use peer\http\HttpConnection;
use util\URI;
use web\auth\Flow;

class OAuth1Flow extends Flow {
  const SESSION_KEY = 'oauth1::flow';

  private $service, $signature, $callback;

  /**
   * Creates a new OAuth 1 flow
   *
   * @param  string|util.URI $service
   * @param  web.auth.oauth.Token|string[]|util.Secret[] $consumer
   * @param  string|util.URI $callback
   */
  public function __construct($service, $consumer, $callback= null) {
    $this->service= rtrim($service, '/');
    $this->signature= new Signature($consumer instanceof Token ? $consumer : new Token(...$consumer));

    // BC: Support deprecated constructor signature without callback
    if (null === $callback) {
      trigger_error('Missing parameter $callback', E_USER_DEPRECATED);
      $this->callback= null;
    } else {
      $this->callback= $callback instanceof URI ? $callback : new URI($callback);
    }
  }

  /**
   * Obtain a request token
   *
   * @param  string $path
   * @param  ?string $token
   * @param  [:var] $params
   * @return var
   * @throws lang.IllegalStateException if fetching fails
   */
  protected function request($path, $token= null, $params= []) {
    $url= $this->service.$path;
    $auth= $this->signature->header('POST', $url, $token ? $params + ['oauth_token' => $token] : $params);

    $r= (new HttpConnection($url))->post($params, [
      'Authorization' => $auth,
      'User-Agent'    => 'XP/OAuth1',
      'Accept'        => 'application/json;q=1.0, */*;q=0.8'
    ]);

    $body= Streams::readAll($r->in());
    if (200 === $r->statusCode()) {
      parse_str($body, $result);
      return $result;
    }

    throw new IllegalStateException('#'.$r->statusCode().' @ '.$url.': '.$body);
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
    if (isset($state['access'])) {
      return new BySignedRequests($this->signature->with(new Token($state['oauth_token'], $state['oauth_token_secret'])));
    }

    $uri= $this->url(true)->resolve($request);
    $server= $request->param('oauth_token');
    if (null === $state || null === $server) {
      $callback= $this->callback ? $uri->resolve($this->callback) : $this->service($uri);

      // Start authenticaton flow by obtaining request token and store for later use
      $token= $this->request('/request_token', null, ['oauth_callback' => $callback]);
      $session->register(self::SESSION_KEY, $token + ['target' => (string)$uri]);
      $session->transmit($response);

      $this->login($response, sprintf(
        '%s/authenticate?oauth_token=%s&oauth_callback=%s',
        $this->service,
        urlencode($token['oauth_token']),
        urlencode($callback)
      ));
      return null;
    } else if ($state['oauth_token'] === $server) {

      // Back from authentication redirect, upgrade request token to access token
      $access= $this->request('/access_token', $state['oauth_token'], ['oauth_verifier' => $request->param('oauth_verifier')]);
      $session->register(self::SESSION_KEY, $access + ['access' => true]);
      $session->transmit($response);

      // Redirect to self
      $this->finalize($response, $state['target']);
      return null;
    }

    throw new IllegalStateException('Flow error, request token '.$state['oauth_token'].' != server token '.$server);
  }
}