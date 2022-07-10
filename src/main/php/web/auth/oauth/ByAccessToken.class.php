<?php namespace web\auth\oauth;

use util\Secret;

class ByAccessToken extends Client {
  private $token, $type, $scope, $expires, $refresh, $id;

  /**
   * Creates a new instance with a given token and type (defaulting to 'Bearer')
   *
   * @param  string|util.Secret $token `access_token`
   * @param  string $type
   * @param  ?string $scope
   * @param  ?int $expires
   * @param  ?string|util.Secret $refresh `refresh_token`
   * @param  ?string|util.Secret $id `id_token`
   */
  public function __construct($token, $type= 'Bearer', $scope= null, $expires= null, $refresh= null, $id= null) {
    $this->token= $token instanceof Secret ? $token : new Secret($token);
    $this->type= $type;
    $this->scope= $scope;
    $this->expires= null === $expires ? null : (int)$expires;
    $this->refresh= null === $refresh ? null : ($refresh instanceof Secret ? $refresh : new Secret($refresh));
    $this->id= null === $id ? null : ($id instanceof Secret ? $id : new Secret($id));
  }

  /** @return util.Secret */
  public function token() { return $this->token; }

  /** @return string */
  public function type() { return $this->type; }

  /** @return ?string */
  public function scope() { return $this->scope; }

  /** @return ?int */
  public function expires() { return $this->expires; }

  /** @return ?util.Secret */
  public function refresh() { return $this->refresh; }

  /** @return ?util.Secret */
  public function id() { return $this->id; }

  /** @return ?[:var] */
  public function refreshable() {
    return null === $this->expires ? null : [
      'expires' => time() + $this->expires,
      'refresh' => $this->refresh ? $this->refresh->reveal() : null
    ];
  }

  /**
   * Authorize request and returns it
   *
   * @param  peer.http.HttpRequest $request
   * @return peer.http.HttpRequest
   */
  public function authorize($request) {
    $request->setHeader('Authorization', $this->type.' '.$this->token->reveal());
    return $request;
  }
}