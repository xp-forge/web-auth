<?php namespace web\auth\oauth;

use io\streams\Streams;
use lang\IllegalStateException;
use peer\http\HttpConnection;
use web\auth\Flow;

class OAuth1Flow implements Flow {
  private $service, $signature;

  /**
   * Creates a new OAuth 1 flow
   *
   * @param  string|util.URI $service
   * @param  web.auth.oauth.Token|string[]|util.Secret[] $consumer
   */
  public function __construct($service, $consumer) {
    $this->service= rtrim($service, '/');
    $this->signature= new Signature($consumer instanceof Token ? $consumer : new Token(...$consumer));
  }

  protected function request($path, $token= null, $params= []) {
    $url= $this->service.$path;
    $auth= $this->signature->header('POST', $url, $token ? $params + ['oauth_token' => $token] : $params);

    $c= new HttpConnection($url);
    $r= $c->post($params, ['Authorization' => $auth, 'User-Agent' => 'XP/OAuth1']);
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
    $token= $session->value('oauth.request');
    if (null === $token) {

      // Start authenticaton flow by obtaining request token and store for later use
      $token= $this->request('/request_token');
      $session->register('oauth.request', $token);

      // Redirect user to authentication
      $response->answer(302);
      $response->header('Location', $this->service.'/authenticate?oauth_token='.urlencode($token['oauth_token']));
      return;
    } else if ($token['oauth_token'] === $request->param('oauth_token')) {

      // Back from authentication redirect, upgrade request token to access token
      $access= $this->request('/access_token', $token['oauth_token'], ['oauth_verifier' => $request->param('oauth_verifier')]);
      $session->register('oauth.access', $access);

      // Redirect back, removing GET parameters
      $response->answer(302);
      $response->header('Location', $request->uri()->using()->param('oauth_token', null)->param('oauth_verifier', null)->create());
      return;
    } else if ($access= $session->value('oauth.access')) {

      // Finally, return an authenticated session
      return new BySignedRequests($this->signature->with(new Token($access['oauth_token'], $access['oauth_token_secret'])));
    }

    throw new IllegalStateException('Flow error');
  }
}