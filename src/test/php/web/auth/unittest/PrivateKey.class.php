<?php namespace web\auth\unittest;

use lang\IllegalStateException;

trait PrivateKey {

  /**
   * Creates a new 2048 bits RSA private key.
   * 
   * @return OpenSSLAsymmetricKey
   * @throws lang.IllegalStateException
   */
  public function newPrivateKey() {
    $options= ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];

    // On Windows, search common locations for openssl.cnf *including*
    // the sample config bundled with the PHP release in `extras/ssl`
    if (0 === strncasecmp(PHP_OS, 'WIN', 3)) {
      $locations= [
        getenv('OPENSSL_CONF') ?: getenv('SSLEAY_CONF'),
        'C:\\Program Files\\Common Files\\SSL\\openssl.cnf',
        'C:\\Program Files (x86)\\Common Files\\SSL\\openssl.cnf',
        dirname(PHP_BINARY).'\\extras\\ssl\\openssl.cnf'
      ];
      foreach ($locations as $location) {
        if (!file_exists($location)) continue;
        $options['config']= $location;
        break;
      }
    }

    if (!($key= openssl_pkey_new($options))) {
      throw new IllegalStateException('Cannot generate private key: '.openssl_error_string());
    }

    return $key;
  }
}
