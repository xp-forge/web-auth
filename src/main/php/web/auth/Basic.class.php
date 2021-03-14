<?php namespace web\auth;

use lang\IllegalArgumentException;
use util\Secret;

/**
 * HTTP basic authentication
 *
 * @see   https://tools.ietf.org/html/rfc2617
 * @test  xp://web.auth.unittest.BasicAuthenticationTest
 */
class Basic extends Authentication {
  const LOGIN = 'function(string, util.Secret): var';
  private $realm, $login;

  /**
   * Creates a basic authentication instance
   *
   * @param  string $realm
   * @param  function(string, util.Secret): var $login
   */
  public function __construct(string $realm, $login) {
    if (!is(self::LOGIN, $login)) {
      throw new IllegalArgumentException('Expected '.self::LOGIN.', have '.typeof($login));
    }

    $this->realm= $realm;
    $this->login= $login;
  }

  /**
   * Returns whether this authentication information is present on the request
   *
   * @param  web.Request $req
   * @return bool
   */
  public function present($req) {
    $auth= $req->header('Authorization');
    return $auth && 1 === sscanf($auth, "Basic %[^\r]", $_);
  }

  /**
   * Executes authentication flow. On success, the user is looked up and
   * registered in the session under a key "user".
   *
   * @param  web.Request $req
   * @param  web.Response $res
   * @param  web.filters.Invocation $invocation
   * @return var
   */
  public function filter($req, $res, $invocation) {
    if (1 === sscanf($req->header('Authorization', ''), "Basic %[^\r]", $credentials)) {
      if (2 === sscanf(base64_decode($credentials), "%[^:]:%[^\r]", $username, $password)) {
        $secret= new Secret($password);
        if (null !== ($user= ($this->login)($username, $secret))) {
          return $invocation->proceed($req->pass('user', $user), $res);
        }
      }
    }

    $res->header('WWW-Authenticate', 'Basic realm="'.$this->realm.'"');
    $res->answer(401, 'Unauthorized');
  }
}