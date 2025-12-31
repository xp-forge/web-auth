<?php namespace web\auth\unittest;

use lang\IllegalStateException;
use test\{Assert, Test, Values};
use web\auth\oauth\JWT;

class JWTTest {
  const ISSUER= 'xp-testing';
  const HEADER= ['alg' => 'RS256', 'typ' => 'JWT'];
  const TOKEN= [
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ4cC10ZXN0aW5nI',
    'iwic3ViIjoidGVzdCJ9.LAI3asY6s3ObdWchBYmVBh4hVNztWlTLAdKA-6fqYx',
    'tsouo90G9q0OXQ26axz9j0CbQ-nLBeDVSQ4c1ay69Ot13OnGsBSL1mT9WVgCyu',
    'JUInDCtD34j3hefqmVz4lVK6-QI7jpSCeff-W-T3rom7-atnQ3UZBNlX3CBzNi',
    'ZDMA1WRubcbfKjD0D8D6hSxq7LL0YrDhC8xvAtlzB3NMZUDJ56GAG1tAIAuMsP',
    '8iQFQNp97Wxa-13Z08etsdhj5-mZvY0251NOa3EUe2ykwh9FSLowUqX0aNppPI',
    '8sVGVsfoiu2DyElLBNcya6_sN4xm7otS3vA-prNRg66SUn-7QGWw'
  ];
  const PRIVATE_KEY= <<<'PRIVATE_KEY'
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAsxFFSy1nXqchsH5sNr7v0bYrP5KAlKUPZxa2rNCD0uxsYy2+
    K9XFTCU2uQJFpkBkiUMUdYTfSoI7lqUkgYf2X30S8Bc9hV0C656yK7kA00EOZrkD
    gpooJwGjDd9R60baHdSYnMh9EIiCB8XR8C22Ha3Uso0v3EsDvor5k3HzN8dkBJkZ
    s9fJqf/K5P22HDuC/EhIDxdrODhwhoshpydN+FHwt8V4uuhULOvj8mFW0ooUUuyY
    T/qWtjOmV0KhIZmtIyQBwe62SKxNQttdJ6wq55gCTmWIWw26Q4x/Q8bcHgF13yEa
    9NcG6AWHiU3ln7tqqplPApk1erKWjdXERbpD0QIDAQABAoIBAQCTzTeS28EswWrv
    UQplDajJQkHkUTpMdwmFn5vcfKeyW28DVehYKjSVq0nF33g5x4C0Q2gJsEjWKTSi
    HWFKgTz8iDIvdh9Tivg0H2MU77kcpeALLb8V98QYniNF+gSV3H+Ai9AD6QBBu0sI
    u2GTi0d8q9SaJCtS+5/1kKR77VxBtrLnMFMC11DoB1bazRNBZsBC6NvTZVJZGdvq
    q86CF6s+DKCTTN0J5GcQVX8hvNKyGe8n6rUyxflDejJXEzo/k+zeitVvPOie3cv6
    fOyfslacM8Gapy7dyXYnkTX4gswyGVCbwO2BNFWr1xvpadXE9hK4VlqIC3t1GzYq
    Px0Y0eJ5AoGBANvPY61WPfdRuSpzhlmVrq+urvfFw9iRj1nbMmwuG2VwWU+DyCnr
    Oawl/OoshVBg31Z7LMWQuLjTT1uVb+rVLxmzpf6+/6vZhKSTwjJT9gOOQOhNFAZV
    1D6+y0FZrIfVDubaqheWEKk7RAKddInZEdUMEY6zA73cu+9RixdPOs/HAoGBANCM
    pmpkMkkAUQFzDBghE2QXRh9I7taIM32SAo/xz0dVfrVAFDYpKsQ127xghJNwmCy8
    SFJ/rOC/ULvDZXXzmvfngolA170T6QjRlaLlqX9e+F4EzDvB0C9BEGs3Ha+byZwV
    Y/kcCbIhV5j3N7zpXxFmkW4HmjiWN8t9Mlgeb3+nAoGACHZMdRDb49iOk1bNNkev
    6O2FqN5BMuYvqZrprwZ7YYVYutns68g1eS4hNXavTy/biT3GtHhk1CC2bmUrYNQC
    MzAaVNtPhnMiSx+xGzTmRK7GSuskuTW2rQ+1TXfBT51hLHwAjlXloE46yQr8wI3N
    xPDpACBeJYII7iaqfyQ6tGMCgYBCzZsNH3VgHwLTxQeNvyKYAECNCu6+t7hOs/Ow
    KlQsVH2XD6SpyLwTR/FQQVaWaA3G3rUIAC/fekkhLDEW/GaanIUa9DNnNLaEBaa6
    HHkT/NbwPvcw+R93046v2WLf+rY1EkEI7etJLRcDP8WR9OtoBoP1S+gh0jSjMUJs
    KaurpwKBgCUUXwwsSkRMe/4rlabVZM5H12sT3diQPaYcDCdQZa1sIl0qHwDzzYcy
    M4FHekELoBUO+SI7Okz9icDJiyjg0H8/5jYqSNZG2ezSw1o+Jbu0HYj2BqkqpGUf
    Q6K1e9bCewMlfCzCSs6KdISPnLMA91tUJb2KLr45B1FONc/3pEg3
    -----END RSA PRIVATE KEY-----
    PRIVATE_KEY
  ;
  const PUBLIC_KEY= <<<'PUBLIC_KEY'
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsxFFSy1nXqchsH5sNr7v
    0bYrP5KAlKUPZxa2rNCD0uxsYy2+K9XFTCU2uQJFpkBkiUMUdYTfSoI7lqUkgYf2
    X30S8Bc9hV0C656yK7kA00EOZrkDgpooJwGjDd9R60baHdSYnMh9EIiCB8XR8C22
    Ha3Uso0v3EsDvor5k3HzN8dkBJkZs9fJqf/K5P22HDuC/EhIDxdrODhwhoshpydN
    +FHwt8V4uuhULOvj8mFW0ooUUuyYT/qWtjOmV0KhIZmtIyQBwe62SKxNQttdJ6wq
    55gCTmWIWw26Q4x/Q8bcHgF13yEa9NcG6AWHiU3ln7tqqplPApk1erKWjdXERbpD
    0QIDAQAB
    -----END PUBLIC KEY-----
    PUBLIC_KEY
  ;

  /** @return iterable */
  private function malformed() {
    yield [null, '/Expected \[header\].\[payload\].\[signature\]/'];
    yield ['', '/Expected \[header\].\[payload\].\[signature\]/'];
    yield ['a.b', '/Expected \[header\].\[payload\].\[signature\]/'];
    yield ['a.b.c', '/Header parsing error/'];
    yield ['e30.b.c', '/Unsupported algorithm \(null\)/'];
    yield ['eyJhbGciOiJSUzI1NiJ9.b.c', '/Payload parsing error/'];
    yield ['eyJhbGciOiJIUzI1NiJ9.b.c', '/Unsupported algorithm HS256/'];
    yield ['eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.c', '/Signature mismatch/'];
  }

  #[Test, Values([['Test', 'VGVzdA'], ["\xfb", '-w'], ["\xff", '_w']])]
  public function encode($input, $encoded) {
    Assert::equals($encoded, JWT::encode($input));
  }

  #[Test, Values([['VGVzdA', 'Test'], ['-w', "\xfb"], ['_w', "\xff"]])]
  public function decode($input, $decoded) {
    Assert::equals($decoded, JWT::decode($input));
  }

  #[Test]
  public function header() {
    Assert::equals(self::HEADER, (new JWT(self::HEADER, []))->header());
  }

  #[Test]
  public function alg_defaults_to_RS256() {
    Assert::equals(self::HEADER, (new JWT(['typ' => 'JWT'], []))->header());
  }

  #[Test]
  public function payload() {
    $payload= ['iss' => self::ISSUER, 'sub' => 'test'];
    Assert::equals($payload, (new JWT(self::HEADER, $payload))->payload());
  }

  #[Test, Values([['iat', 6100], ['name', 'Test'], ['loggedInAs', null]])]
  public function claim($name, $expected) {
    Assert::equals($expected, (new JWT(self::HEADER, ['iat' => 6100, 'name' => 'Test']))->claim($name));
  }

  #[Test]
  public function sign() {
    $jwt= new JWT(self::HEADER, ['iss' => self::ISSUER, 'sub' => 'test']);
    Assert::equals(implode('', self::TOKEN), $jwt->sign(self::PRIVATE_KEY));
  }

  #[Test]
  public function from() {
    Assert::equals(
      new JWT(self::HEADER, ['iss' => self::ISSUER, 'sub' => 'test']),
      JWT::from(implode('', self::TOKEN), self::PUBLIC_KEY)
    );
  }

  #[Test]
  public function try_from() {
    Assert::equals(
      new JWT(self::HEADER, ['iss' => self::ISSUER, 'sub' => 'test']),
      JWT::tryFrom(implode('', self::TOKEN), self::PUBLIC_KEY)
    );
  }

  #[Test, Values(from: 'malformed')]
  public function from_malformed($token, $error) {
    try {
      JWT::from($token, self::PUBLIC_KEY);
      Assert::throws(IllegalStateException::class, fn() => null);
    } catch (IllegalStateException $expected) {
      Assert::matches($error, $expected->getMessage());
    }
  }

  #[Test, Values(from: 'malformed')]
  public function try_from_malformed($token, $error) {
    Assert::null(JWT::tryFrom($token, self::PUBLIC_KEY));
  }
}