<?php namespace web\auth\oauth;

use peer\URL;
use peer\http\{HttpConnection, HttpRequest, RequestData};

abstract class Client {
  const USER_AGENT = 'XP/OAuth';

  /**
   * Sends a HTTP request and returns a given HTTP response
   *
   * @param  peer.http.HttpRequest $request
   * @return peer.http.HttpResponse
   */
  protected function send($request) {
    return (new HttpConnection($request->url))->send($request);
  }

  /**
   * Authorize request and returns it
   *
   * @param  peer.http.HttpRequest $request
   * @return peer.http.HttpRequest
   */
  public abstract function authorize($request);

  /**
   * Fetch a given URL with options, which may include the following:
   *
   * - method: HTTP method to use, defaults to 'GET'
   * - params: Parameters to send with the request, defaults to empty array
   * - body: Body to send with the request, defaults to sending parameters
   * - headers: Additional headers to append to the request
   *
   * @param  string $url
   * @param  [:var] $options
   * @return web.auth.oauth.Response
   */
  public function fetch($url, $options= []) {
    $r= new HttpRequest(new URL($url));
    $r->setMethod($options['method'] ?? 'GET');
    $r->setParameters(isset($options['body']) ? new RequestData($options['body']) : $options['params'] ?? []);
    $r->addHeaders(($options['headers'] ?? []) + ['Accept' => 'application/json', 'User-Agent' => self::USER_AGENT]);

    return new Response($this->send($this->authorize($r)));
  }
}