<?php namespace web\auth\oauth;

use peer\http\HttpConnection;
use util\Secret;

class ByAccessToken implements Session {
  private $token, $type;

  public function __construct($token, $type= 'Bearer') {
    $this->token= $token instanceof Secret ? $token : new Secret($token);
    $this->type= $type;
  }

  public function fetch($url, $params= []) {
    $c= new HttpConnection($url);
    return new Response($c->get($params, [
      'Accept'        => 'application/json',
      'User-Agent'    => 'XP/OAuth2',
      'Authorization' => $this->type.' '.$this->token->reveal()
    ]));
  }

  /** @return util.Secret */
  public function token() { return $this->token; }

  /** @return string */
  public function type() { return $this->type; }
}