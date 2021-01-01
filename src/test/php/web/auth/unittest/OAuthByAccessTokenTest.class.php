<?php namespace web\auth\unittest;

use io\streams\MemoryInputStream;
use peer\http\HttpResponse;
use unittest\{Assert, Test};
use web\auth\oauth\ByAccessToken;

class OAuthByAccessTokenTest {
  const TOKEN = '073204f68de382213e92c5792b07b33b';

  /** Returns a fixture which records HTTP requests instead of actually sending them */
  private function newFixture() {
    return new class(self::TOKEN, 'Bearer') extends ByAccessToken {
      public $requests= [];

      /** Overriden from base class */
      protected function send($request) {
        $this->requests[]= $request;
        return new HttpResponse(new MemoryInputStream("HTTP/1.0 200 OK\r\n\r\n"));
      }
    };
  }

  #[Test]
  public function can_create() {
    new ByAccessToken(self::TOKEN, 'Bearer');
  }

  #[Test]
  public function token() {
    Assert::equals(self::TOKEN, (new ByAccessToken(self::TOKEN, 'Bearer'))->token()->reveal());
  }

  #[Test]
  public function type() {
    Assert::equals('Bearer', (new ByAccessToken(self::TOKEN, 'Bearer'))->type());
  }

  #[Test]
  public function type_defaults_to_bearer() {
    Assert::equals('Bearer', (new ByAccessToken(self::TOKEN))->type());
  }

  #[Test]
  public function fetch_uses_get_by_default() {
    $fixture= $this->newFixture();
    $fixture->fetch('https://example.org/');

    Assert::equals(
      "GET / HTTP/1.1\r\n".
      "Connection: close\r\n".
      "Host: example.org\r\n".
      "Accept: application/json\r\n".
      "User-Agent: XP/OAuth\r\n".
      "Authorization: Bearer 073204f68de382213e92c5792b07b33b\r\n\r\n",
      $fixture->requests[0]->getRequestString()
    );
  }

  #[Test]
  public function fetch_using_post() {
    $fixture= $this->newFixture();
    $fixture->fetch('https://example.org/', ['method' => 'POST', 'body' => 'Test', 'headers' => [
      'Content-Type' => 'text/plain'
    ]]);

    Assert::equals(
      "POST / HTTP/1.1\r\n".
      "Connection: close\r\n".
      "Host: example.org\r\n".
      "Content-Type: text/plain\r\n".
      "Accept: application/json\r\n".
      "User-Agent: XP/OAuth\r\n".
      "Authorization: Bearer 073204f68de382213e92c5792b07b33b\r\n".
      "Content-Length: 4\r\n\r\n".
      "Test",
      $fixture->requests[0]->getRequestString()
    );
  }
}