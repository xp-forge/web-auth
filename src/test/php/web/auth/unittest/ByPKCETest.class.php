<?php namespace web\auth\unittest;

use lang\IllegalArgumentException;
use test\{Assert, Expect, Test, Values};
use web\auth\oauth\ByPKCE;

class ByPKCETest {
  const CLIENT_ID= 'b2ba8814';
  const TEST_SEED= ['verifier' => 'test-challenge'];

  /** @return iterable */
  private function challenges() {
    yield ['S256', 'Xuq1l4Pllrvf6AJ2BfBwnQFQKBK7dnKAbolZ3zvWFlw']; // base64(sha256(TEST_SEED[verifier]))
    yield ['plain', 'test-challenge'];
  }

  #[Test, Values(['S256', 'plain'])]
  public function can_create_with($method) {
    new ByPKCE(self::CLIENT_ID, $method);
  }

  #[Test, Values(['S128', 'invalid']), Expect(IllegalArgumentException::class)]
  public function unsupported($method) {
    new ByPKCE(self::CLIENT_ID, $method);
  }

  #[Test]
  public function seed_creates_verifier() {
    Assert::matches(
      '/^[a-zA-Z0-9._~-]{64}$/',
      (new ByPKCE(self::CLIENT_ID, 'S256'))->seed()['verifier']
    );
  }

  #[Test, Values(from: 'challenges')]
  public function pass($method, $challenge) {
    Assert::equals(
      ['code_challenge' => $challenge, 'code_challenge_method' => $method],
      (new ByPKCE(self::CLIENT_ID, $method))->pass(self::TEST_SEED)
    );
  }

  #[Test]
  public function params() {
    Assert::equals(
      ['client_id' => self::CLIENT_ID, 'code_verifier' => 'test-challenge'],
      (new ByPKCE(self::CLIENT_ID, 'S256'))->params('https://test/oauth/tokens', self::TEST_SEED)
    );
  }
}