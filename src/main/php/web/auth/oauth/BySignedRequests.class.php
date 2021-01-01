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
   * @see    https://stackoverflow.com/questions/10770513/post-request-with-oauth
   * @param  peer.http.HttpRequest $request
   * @return peer.http.HttpRequest
   */
  public function authorize($request) {
    $request->setHeader('Authorization', $this->signature->header(
      $request->method,
      $request->url->getURL(),
      is_array($request->parameters) ? $request->parameters : []
    ));
    return $request;
  }

  /** @return web.auth.oauth.Signature */
  public function signature() { return $this->signature; }
}