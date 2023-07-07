<?php namespace web\auth\oauth;

use peer\http\HttpConnection;
use lang\IllegalStateException;
use io\streams\Streams;

class OAuth2Backend {
  private $conn, $credentials;
  private $headers= [];

  /**
   * Creates a new OAuth 2 backend
   *
   * @param  string|util.URI|peer.http.HttpConnection $endpoint
   * @param  ?web.auth.oauth.Credentials|(string|util.Secret)[] $credentials
   */
  public function __construct($endpoint, $credentials= null) {
    $this->conn= $endpoint instanceof HttpConnection ? $endpoint : new HttpConnection($endpoint);
    $credentials && $this->using($credentials);
  }

  /**
   * Specifies credentials to use
   *
   * @param  web.auth.oauth.Credentials|(string|util.Secret)[] $credentials
   * @return self
   */
  public function using($credentials) {
    if ($credentials instanceof Credentials) {
      $this->credentials= $credentials;
    } else if ($credentials instanceof Token) { // BC
      $this->credentials= new BySecret($credentials->key()->reveal(), $credentials->secret());
    } else {
      $this->credentials= new BySecret(...$credentials);
    }
    return $this;
  }

  /**
   * Specifies headers to add to request
   *
   * @param  [:string] $headers
   * @return self
   */
  public function with($headers) {
    $this->headers= $headers;
    return $this;
  }

  /** @return string */
  public function clientId() { return $this->credentials->key; }

  /**
   * Performs HTTP request
   *
   * @param  [:string] $payload POST parameters
   * @return [:string] Token
   * @throws lang.IllegalStateException
   */
  protected function request($payload) {
    $r= $this->conn->post($payload, $this->headers + [
      'Accept'     => 'application/x-www-form-urlencoded, application/json',
      'User-Agent' => 'XP/OAuth2'
    ]);

    $body= Streams::readAll($r->in());
    if (200 !== $r->statusCode()) {
      throw new IllegalStateException('Cannot get access token (#'.$r->statusCode().'): '.$body);
    }

    $type= $r->header('Content-Type')[0];
    if (strstr($type, 'application/json')) {
      return json_decode($body, true);
    } else {
      parse_str($body, $token);
      return $token;
    }
  }

  /**
   * Acquires a grant
   *
   * @param  [:string] $grant
   * @return [:string]
   */
  public function acquire($grant) {
    return $this->request($this->credentials->params($this->conn->getUrl()->getCanonicalURL()) + $grant);
  }
}