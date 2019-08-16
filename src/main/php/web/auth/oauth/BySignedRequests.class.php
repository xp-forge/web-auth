<?php namespace web\auth\oauth;

use peer\http\HttpConnection;

class BySignedRequests implements Session {

  public function __construct(Signature $signature) {
    $this->signature= $signature;
  }

  public function fetch($url, $params= []) {
    $c= new HttpConnection($url);
    return new Response($c->get($params, [
      'Accept'        => 'application/json',
      'User-Agent'    => 'XP/OAuth1',
      'Authorization' => $this->signature->header('GET', $url, $params),
    ]));
  }
}