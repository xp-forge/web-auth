<?php namespace web\auth\oauth;

use io\streams\Streams;
use lang\IllegalStateException;
use peer\http\HttpConnection;
use util\URI;

/** @test web.auth.unittest.OAuth1FlowTest */
class OAuth1Flow extends OAuthFlow {
  private $service, $signature;

  /**
   * Creates a new OAuth 1 flow
   *
   * @param  string|util.URI $service
   * @param  web.auth.oauth.Credentials|(string|util.Secret)[] $consumer
   * @param  string|util.URI $callback
   */
  public function __construct($service, $consumer, $callback= null) {
    $this->namespace= 'oauth1::flow';
    $this->service= rtrim($service, '/');

    // BC: Support web.auth.oauth.Token instances
    if ($consumer instanceof Credentials) {
      $this->signature= new Signature($consumer);
    } else if ($consumer instanceof Token) {
      $this->signature= new Signature(new BySecret($consumer->key()->reveal(), $consumer->secret()));
    } else {
      $this->signature= new Signature(new BySecret(...$consumer));
    }

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
    $state= $session->value($this->namespace);

    // We have an access token, reset state and return an authenticated session
    if (isset($state['access'])) {
      $session->remove($this->namespace);
      return new BySignedRequests($this->signature->with(new BySecret($state['oauth_token'], $state['oauth_token_secret'])));
    }

    // Store fragment, then make redirection continue (see redirect() above)
    if ($fragment= $request->param(self::FRAGMENT)) {
      if ($t= strstr($state['target'], '#', true)) {
        $state['target']= $t.'#'.$fragment;
      } else {
        $state['target'].= '#'.$fragment;
      }

      $session->register($this->namespace, $state);
      $session->transmit($response);
      $response->send('document.location.replace(target)', 'text/javascript');
      return null;
    }

    $uri= $this->url(true)->resolve($request);
    $callback= $this->callback ? $uri->resolve($this->callback) : $this->service($uri);

    // Start authenticaton flow by obtaining request token and store for later use
    $server= $request->param('oauth_token');
    if (null === $state || null === $server) {
      $token= $this->request('/request_token', null, ['oauth_callback' => $callback]);
      $session->register($this->namespace, $token + ['target' => (string)$uri]);
      $session->transmit($response);

      // Redirect the user to the authorization page
      $target= sprintf(
        '%s/authenticate?oauth_token=%s&oauth_callback=%s',
        $this->service,
        urlencode($token['oauth_token']),
        urlencode($callback)
      );

      // If a URL fragment is present, call ourselves to capture it inside the
      // session; otherwise redirect the OAuth authentication service directly.
      $this->redirect($response, $target, sprintf('
        var target = "%1$s";
        var hash = document.location.hash.substring(1);

        if (hash) {
          var s = document.createElement("script");
          s.src = "%2$s?%3$s=" + encodeURIComponent(hash) + "&" + Math.random();
          document.body.appendChild(s);
        } else {
          document.location.replace(target);
        }',
        $target,
        $uri,
        self::FRAGMENT
      ));
      return null;
    } else if ($state['oauth_token'] === $server) {

      // Back from authentication redirect, upgrade request token to access token
      $access= $this->request('/access_token', $state['oauth_token'], ['oauth_verifier' => $request->param('oauth_verifier')]);
      $session->register($this->namespace, $access + ['access' => true]);
      $session->transmit($response);

      // Redirect to self
      $this->finalize($response, $state['target']);
      return null;
    }

    throw new IllegalStateException('Flow error, request token '.$state['oauth_token'].' != server token '.$server);
  }
}