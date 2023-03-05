<?php namespace web\auth\unittest;

use io\streams\MemoryInputStream;
use peer\http\HttpResponse;
use test\{Assert, Test};
use web\auth\oauth\ByAccessToken;

class OAuthByAccessTokenTest {
  const TOKEN   = '073204f68de382213e92c5792b07b33b';
  const REFRESH = '0.ARAAVA2S7uRGHk6qw_dU-sy2k0tYTL';
  const ID      = 'eyJ0eXJ9.eyJhdWQiOiJJ9.EHgx6iY0P';

  /** Returns a fixture which records HTTP requests instead of actually sending them */
  private function newFixture() {
    return new class(self::TOKEN, 'Bearer', 'profile', 3599, self::REFRESH, self::ID) extends ByAccessToken {
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
    Assert::equals(self::TOKEN, $this->newFixture()->token()->reveal());
  }

  #[Test]
  public function type() {
    Assert::equals('Bearer', $this->newFixture()->type());
  }

  #[Test]
  public function scope() {
    Assert::equals('profile', $this->newFixture()->scope());
  }

  #[Test]
  public function expires() {
    Assert::equals(3599, $this->newFixture()->expires());
  }

  #[Test]
  public function refresh() {
    Assert::equals(self::REFRESH, $this->newFixture()->refresh()->reveal());
  }

  #[Test]
  public function id() {
    Assert::equals(self::ID, $this->newFixture()->id()->reveal());
  }

  #[Test]
  public function type_defaults_to_bearer() {
    Assert::equals('Bearer', (new ByAccessToken(self::TOKEN))->type());
  }

  #[Test]
  public function scope_defaults_to_null() {
    Assert::null((new ByAccessToken(self::TOKEN))->scope());
  }

  #[Test]
  public function expires_defaults_to_null() {
    Assert::null((new ByAccessToken(self::TOKEN))->expires());
  }

  #[Test]
  public function refresh_defaults_to_null() {
    Assert::null((new ByAccessToken(self::TOKEN))->refresh());
  }

  #[Test]
  public function id_defaults_to_null() {
    Assert::null((new ByAccessToken(self::TOKEN))->id());
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