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
    $stored= $session->value($this->namespace) ?? ['flows' => []];

    // We have an access token, remove and return an authenticated session. The
    // authentication implementation registers the user and transmits the session.
    if ($token= $stored['token'] ?? null) {
      unset($stored['token']);
      $session->register($this->namespace, $stored);

      return new BySignedRequests($this->signature->with(new BySecret(
        $token['oauth_token'],
        $token['oauth_token_secret']
      )));
    }

    // Enter authentication flow, resolving callback URI against the curren request.
    $uri= $this->url(true)->resolve($request);
    $callback= $this->callback ? $uri->resolve($this->callback) : $this->service($uri);

    // Check whether we are continuing an existing authentication flow based on the
    // state given by the server and our session; or if we need to start a new one.
    if (null === ($state= $request->param('oauth_token'))) {
      $flow= null;
    } else {
      $flow= $this->flow($state, $stored);
    }

    if (null === $flow) {
      $state= $this->request('/request_token', null, ['oauth_callback' => $callback])['oauth_token'];

      $stored['flows'][$state]= ['uri' => (string)$uri, 'seed' => []];
      $session->register($this->namespace, $stored);
      $session->transmit($response);

      // Redirect the user to the authorization page
      $token= urlencode($state);
      $target= sprintf('%s/authenticate?oauth_token=%s&oauth_callback=%s', $this->service, $token, urlencode($callback));

      // If a URL fragment is present, call ourselves to capture it inside the
      // session; otherwise redirect the OAuth authentication service directly.
      $separator= self::FRAGMENT;
      return $this->redirect($response, $target, <<<JS
        var hash = document.location.hash;
        if (hash) {
          var target = '{$target}';
          var s = document.createElement('script');
          s.src = '{$uri}?oauth_token={$token}&{$separator}=' + encodeURIComponent(hash.substring(1)) + '&' + Math.random();
          document.body.appendChild(s);
        } else {
          document.location.replace('{$target}');
        }
        JS
      );
    } else if ($fragment= $request->param(self::FRAGMENT)) {

      // Caputre fragment, then continue redirection, see the script above
      $flow['uri']= substr($flow['uri'], 0, strcspn($flow['uri'], '#')).'#'.$fragment;
      $stored['flows'][$state]= $flow;

      $session->register($this->namespace, $stored);
      $session->transmit($response);
      $response->send('document.location.replace(target);', 'text/javascript');
      return null;
    } else {

      // Back from authentication redirect, upgrade request token to access token
      $stored['token']= $this->request(
        '/access_token',
        $state,
        ['oauth_verifier' => $request->param('oauth_verifier')]
      );

      unset($stored['flows'][$state], $stored['flow'][$state]);
      $session->register($this->namespace, $stored);
      $session->transmit($response);

      // Redirect to self, using captured fragment if present
      return $this->finalize($response, $flow['uri']);
    }
  }
}