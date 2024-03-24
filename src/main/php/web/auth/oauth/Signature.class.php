<?php namespace web\auth\oauth;

class Signature {
  private $consumer, $token;

  /**
   * Creates a new signature
   *
   * @param  web.auth.oauth.BySecret $consumer
   * @param  ?web.auth.oauth.BySecret $token
   */
  public function __construct($consumer, $token= null) {
    $this->consumer= $consumer;
    $this->token= $token;
  }

  public function with(BySecret $token) {
    return new self($this->consumer, $token);
  }

  public function header($method, $url, $parameters= []) {
    $parameters += [
      'oauth_version'          => '1.0',
      'oauth_nonce'            => md5(microtime(true)),
      'oauth_timestamp'        => time(),
      'oauth_consumer_key'     => $this->consumer->key,
      'oauth_signature_method' => 'HMAC-SHA1',
    ];

    $key= rawurlencode($this->consumer->secret()->reveal()).'&';
    if ($this->token) {
      $parameters+= ['oauth_token' => $this->token->key];
      $key.= rawurlencode($this->token->secret()->reveal());
    }

    uksort($parameters, 'strcmp');

    $base= '';
    foreach ($parameters as $name => $value) {
      $base.= '%26'.$name.'%3D'.rawurlencode(rawurlencode($value));
    }
    $base= $method.'&'.rawurlencode($url).'&'.substr($base, 3);
    $signature= base64_encode(hash_hmac('sha1', $base, $key, true));

    $header= '';
    foreach ($parameters + ['oauth_signature' => $signature] as $key => $value) {
      $header.= ', '.$key.='="'.rawurlencode($value).'"';
    }

    return 'OAuth '.substr($header, 2);
  }
}