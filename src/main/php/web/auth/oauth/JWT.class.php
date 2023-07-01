<?php namespace web\auth\oauth;

use lang\IllegalStateException;

/**
 * Very simple JWT implementation (only supporting `RS256`)
 *
 * @see  https://tools.ietf.org/html/rfc7519
 * @ext  openssl
 */
class JWT {
  private $header, $payload;

  /** Creates a new JWT with a given header and payload */
  public function __construct(array $header, array $payload) {
    $this->header= $header;
    $this->payload= $payload;
  }

  /** URL-safe Base64 encoding */
  public static function base64(string $bytes): string {
    return strtr(rtrim(base64_encode($bytes), '='), '+/', '-_');
  }

  /** Sign JWT and return token */
  public function sign($key): string {
    $input= self::base64(json_encode($this->header)).'.'.self::base64(json_encode($this->payload));

    // Hardcode SHA256 signing via OpenSSL here, would need algorithm-based
    // handling in order for this to be a full implementation, see e.g.
    // https://github.com/firebase/php-jwt/blob/v6.2.0/src/JWT.php#L220
    if (!openssl_sign($input, $signature, openssl_pkey_get_private($key), 'SHA256')) {
      throw new IllegalStateException(openssl_error_string());
    }

    return $input.'.'.self::base64($signature);
  }
}