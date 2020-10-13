<?php namespace web\auth;

use util\Secret;

/**
 * HTTP basic authentication
 *
 * @see   https://tools.ietf.org/html/rfc2617
 * @test  xp://web.auth.unittest.BasicAuthenticationTest
 */
class Basic extends Authentication {
  private $realm, $login;

  /**
   * Creates a basic authentication instance
   *
   * @param  string $realm
   * @param  function(string, util.Secret): var $login
   */
  public function __construct(string $realm, $login) {
    $this->realm= $realm;
    $this->login= cast($login, 'function(string, util.Secret): var');
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
    if (1 === sscanf($req->header('Authorization'), "Basic %[^\r]", $credentials)) {
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