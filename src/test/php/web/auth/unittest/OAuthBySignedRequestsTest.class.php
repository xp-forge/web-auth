<?php namespace web\auth\unittest;

use io\streams\MemoryInputStream;
use peer\http\HttpResponse;
use test\{Assert, Before, Test};
use web\auth\oauth\{BySignedRequests, Signature, Token};

class OAuthBySignedRequestsTest {
  private $signature;

  /** Returns a fixture which records HTTP requests instead of actually sending them */
  private function newFixture() {
    return new class($this->signature) extends BySignedRequests {
      public $requests= [];

      /** Overriden from base class */
      protected function send($request) {
        $this->requests[]= $request;
        return new HttpResponse(new MemoryInputStream("HTTP/1.0 200 OK\r\n\r\n"));
      }
    };
  }

  #[Before]
  public function initialize() {
    $this->signature= new class(new Token('consumer', '073204f68de382213e92c5792b07b33b')) extends Signature {
      public function header($method, $url, $parameters= []) {
        return parent::header($method, $url, $parameters + [
          'oauth_nonce'     => '90a8e9e6d5d4fb731eec44a8ee9dcb65',
          'oauth_timestamp' => 1609499980
        ]);
      }
    };
  }

  #[Test]
  public function can_create() {
    new BySignedRequests($this->signature);
  }

  #[Test]
  public function signature() {
    Assert::equals($this->signature, (new BySignedRequests($this->signature))->signature());
  }

  #[Test]
  public function fetch_uses_get_by_default() {
    $fixture= $this->newFixture();
    $fixture->fetch('https://example.org/');

    $oauth= implode(', ', [
      'oauth_consumer_key="consumer"',
      'oauth_nonce="90a8e9e6d5d4fb731eec44a8ee9dcb65"',
      'oauth_signature_method="HMAC-SHA1"',
      'oauth_timestamp="1609499980"',
      'oauth_version="1.0"',
      'oauth_signature="Tq%2B2ygVW5i49vfhiP0H%2FDr1S7co%3D"'
    ]);
    Assert::equals(
      "GET / HTTP/1.1\r\n".
      "Connection: close\r\n".
      "Host: example.org\r\n".
      "Accept: application/json\r\n".
      "User-Agent: XP/OAuth\r\n".
      "Authorization: OAuth $oauth\r\n\r\n",
      $fixture->requests[0]->getRequestString()
    );
  }

  #[Test]
  public function fetch_using_post() {
    $fixture= $this->newFixture();
    $fixture->fetch('https://example.org/', ['method' => 'POST', 'body' => 'Test', 'headers' => [
      'Content-Type' => 'text/plain'
    ]]);

    $oauth= implode(', ', [
      'oauth_consumer_key="consumer"',
      'oauth_nonce="90a8e9e6d5d4fb731eec44a8ee9dcb65"',
      'oauth_signature_method="HMAC-SHA1"',
      'oauth_timestamp="1609499980"',
      'oauth_version="1.0"',
      'oauth_signature="W411UNnsrt6QhMa3BfQ6G%2FR8SGY%3D"'
    ]);
    Assert::equals(
      "POST / HTTP/1.1\r\n".
      "Connection: close\r\n".
      "Host: example.org\r\n".
      "Content-Type: text/plain\r\n".
      "Accept: application/json\r\n".
      "User-Agent: XP/OAuth\r\n".
      "Authorization: OAuth $oauth\r\n".
      "Content-Length: 4\r\n\r\n".
      "Test",
      $fixture->requests[0]->getRequestString()
    );
  }
}