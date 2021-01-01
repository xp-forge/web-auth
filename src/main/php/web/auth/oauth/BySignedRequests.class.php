<?php namespace web\auth\oauth;

class BySignedRequests extends Client {
  private $signature;

  /** Creates a new instance with a given OAuth1 signature */
  public function __construct(Signature $signature) {
    $this->signature= $signature;
  }

  /**
   * Authorize request and returns it
   *
   * @param  peer.http.HttpRequest $request
   * @return peer.http.HttpRequest
   */
  public function authorize($request) {
    $request->setHeader('Authorization', $this->signature->header(
      $request->method,
      $request->url->getURL(),
      $request->parameters
    ));
    return $request;
  }

  /** @return web.auth.oauth.Signature */
  public function signature() { return $this->signature; }
}