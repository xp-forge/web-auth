<?php namespace web\auth\oauth;

use util\Secret;

class ByAccessToken extends Client {
  private $token, $type;

  /**
   * Creates a new instance with a given token and type (defaulting to 'Bearer')
   *
   * @param  string|util.Secret $token
   * @param  string $type
   */
  public function __construct($token, $type= 'Bearer') {
    $this->token= $token instanceof Secret ? $token : new Secret($token);
    $this->type= $type;
  }

  /**
   * Authenticates request and returns it
   *
   * @param  peer.http.HttpRequest $request
   * @return peer.http.HttpRequest
   */
  public function authenticate($request) {
    $request->addHeaders([
      'Accept'        => 'application/json',
      'User-Agent'    => 'XP/OAuth2',
      'Authorization' => $this->type.' '.$this->token->reveal()
    ]);
    return $request;
  }

  /** @return util.Secret */
  public function token() { return $this->token; }

  /** @return string */
  public function type() { return $this->type; }
}