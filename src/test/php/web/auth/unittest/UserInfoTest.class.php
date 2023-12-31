<?php namespace web\auth\unittest;

use io\streams\MemoryInputStream;
use peer\http\HttpResponse;
use test\{Assert, Expect, Test, Values};
use web\auth\AuthenticationError;
use web\auth\oauth\{UserInfo, Client, Response};

class UserInfoTest {
  const ENDPOINT= 'https://example.com/graph/v1.0/me';

  /* Returns a client whose `fetch()` operation returns the given response */
  public function responding(int $status, array $headers, string $payload): Client {
    return newinstance(Client::class, [], [
      'authorize' => function($request) { return $request; },
      'token'     => function() { return 'TOKEN'; },
      'fetch'     => function($url, $options= []) use($status, $headers, $payload) {
        $message= "HTTP/1.1 {$status} ...\r\n";
        foreach ($headers + ['Content-Length' => strlen($payload)] as $name => $value) {
          $message.= "{$name}: {$value}\r\n";
        }
        return new Response(new HttpResponse(new MemoryInputStream($message."\r\n".$payload)));
      }
    ]);
  }

  /** @return iterable */
  private function userResponses() {
    yield ['application/json', '{"id":"root"}'];
    yield ['application/json;charset=utf-8', '{"id":"root"}'];
    yield ['application/vnd.github+json', '{"id":"root"}'];
    yield ['application/x-www-form-urlencoded', 'id=root'];
  }

  #[Test]
  public function can_create() {
    new UserInfo(self::ENDPOINT);
  }

  #[Test, Values(from: 'userResponses')]
  public function fetch($mimeType, $payload) {
    $fixture= new UserInfo(self::ENDPOINT);
    Assert::equals(
      ['id' => 'root'],
      $fixture($this->responding(200, ['Content-Type' => $mimeType], $payload))
    );
  }

  #[Test, Expect(AuthenticationError::class), Values([[400, 'Bad Request'], [500, 'Internal Server Error']])]
  public function fetch_raises_exception_when_endpoint_fails($status, $message) {
    $fixture= new UserInfo(self::ENDPOINT);
    $fixture($this->responding($status, ['Content-Type' => 'text/plain'], $message));
  }

  #[Test]
  public function map_functions_executed() {
    $fixture= (new UserInfo(self::ENDPOINT))
      ->map(function($user) { return ['first' => $user]; })
      ->map(function($user) { return ['second' => $user, 'aggregated' => true]; })
    ;
    Assert::equals(
      ['second' => ['first' => ['id' => 6100]], 'aggregated' => true],
      $fixture($this->responding(200, ['Content-Type' => 'application/json'], '{"id":6100}'))
    );
  }

  #[Test]
  public function map_generators_executed() {
    $fixture= (new UserInfo(self::ENDPOINT))
      ->map(function($user) { yield 'first' => $user; })
      ->map(function($user) { yield 'second' => $user; yield 'aggregated' => true; })
    ;
    Assert::equals(
      ['second' => ['first' => ['id' => 6100]], 'aggregated' => true],
      $fixture($this->responding(200, ['Content-Type' => 'application/json'], '{"id":6100}'))
    );
  }

  #[Test]
  public function map_functions_have_access_to_client() {
    $fixture= (new UserInfo(self::ENDPOINT))->map(function($user, $client) {
      return ['user' => $user, 'token' => $client->token()];
    });
    Assert::equals(
      ['user' => ['id' => 6100], 'token' => 'TOKEN'],
      $fixture($this->responding(200, ['Content-Type' => 'application/json'], '{"id":6100}'))
    );
  }
}