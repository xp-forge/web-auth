<?php namespace web\auth\unittest;

use lang\IllegalArgumentException;
use test\{Assert, Before, Expect, Test, Values};
use test\verify\Runtime;
use web\auth\oauth\ByCertificate;

#[Runtime(extensions: ['openssl'])]
class ByCertificateTest {
  const CLIENT_ID   = 'b2ba8814';
  const FINGERPRINT = 'd41d8cd98f00b204e9800998ecf8427e';
  const ENDPOINT    = 'https://login.example.com/oauth/token';

  private $privateKey;

  #[Before]
  public function privateKey() {
    $this->privateKey= openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
  }

  #[Test]
  public function can_create() {
    new ByCertificate(self::CLIENT_ID, self::FINGERPRINT, $this->privateKey);
  }

  #[Test, Expect(IllegalArgumentException::class)]
  public function invalid_private_key() {
    new ByCertificate(self::CLIENT_ID, self::FINGERPRINT, 'not.a.private.key');
  }

  #[Test]
  public function clientId_member() {
    Assert::equals(self::CLIENT_ID, (new ByCertificate(self::CLIENT_ID, self::FINGERPRINT, $this->privateKey))->clientId);
  }

  #[Test]
  public function client_id_and_assertion_type_in_params() {
    $params= (new ByCertificate(self::CLIENT_ID, self::FINGERPRINT, $this->privateKey))->params(self::ENDPOINT);

    Assert::equals(self::CLIENT_ID, $params['client_id']);
    Assert::equals('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $params['client_assertion_type']);
  }

  #[Test, Values(['d41d8cd98f00b204', 'D41D8CD98F00B204', 'D4:1D:8C:D9:8F:00:B2:04'])]
  public function jwt_headers_with($fingerprint) {
    $params= (new ByCertificate(self::CLIENT_ID, $fingerprint, $this->privateKey))->params(self::ENDPOINT);
    $headers= json_decode(base64_decode(explode('.', $params['client_assertion'])[0]), true);

    Assert::equals(['alg' => 'RS256', 'typ' => 'JWT', 'x5t' => '1B2M2Y8AsgQ'], $headers);
  }

  #[Test, Values([3600, 86400])]
  public function jwt_payload_with($validity) {
    $time= time();
    $params= (new ByCertificate(self::CLIENT_ID, self::FINGERPRINT, $this->privateKey, $validity))->params(self::ENDPOINT, $time);
    $payload= json_decode(base64_decode(explode('.', $params['client_assertion'])[1]), true);

    Assert::equals(
      [
        'aud' => self::ENDPOINT,
        'exp' => $time + $validity,
        'iss' => self::CLIENT_ID,
        'jti' => $payload['jti'],  // Random time-based UUID
        'nbf' => $time,
        'sub' => self::CLIENT_ID,
      ],
      $payload
    );
  }
}