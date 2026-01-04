<?php namespace web\auth;

use lang\Throwable;
use util\Random;
use web\auth\Authorization;
use web\session\Sessions;

/** @test web.auth.unittest.SessionBasedTest */
class SessionBased extends Authentication {
  const TOKEN_LENGTH= 32;
  const IS_NAVIGATION= ['navigate', null];

  private static $random;
  private $flow, $sessions, $lookup;

  static function __static() {
    self::$random= new Random();
  }

  /**
   * Creates a login instance
   *
   * @param  web.auth.Flow $flow
   * @param  web.session.Sessions $sessions
   * @param  function(var): var $lookup Lookup function for users
   */
  public function __construct(Flow $flow, Sessions $sessions, $lookup= null) {
    $this->flow= $flow;
    $this->sessions= $sessions;
    $this->lookup= $lookup;
  }

  /**
   * Returns whether this authentication information is present on the request
   *
   * @param  web.Request $req
   * @return bool
   */
  public function present($req) {
    if ($session= $this->sessions->locate($req)) {
      return null !== ($session->value('auth') ?? $session->value('user'));
    }
    return false;
  }

  /**
   * Authorizes a given session and returns the user
   *
   * @param  web.session.ISession
   * @param  var $result
   * @return var
   */
  private function authorize($session, $result) {
    $user= $this->lookup ? ($this->lookup)($result) : $result;
    $session->register('auth', [$result instanceof Authorization ? $result->claims() : null, $user]);
    return $user;
  }

  /**
   * Executes authentication flow. On success, the user is looked up and
   * registered in the session under a key "user".
   *
   * @param  web.Request $request
   * @param  web.Response $response
   * @param  web.filters.Invocation
   * @return var
   */
  public function filter($req, $res, $invocation) {
    if ($session= $this->sessions->locate($req)) {
      [$claims, $user]= $session->value('auth') ?? [null, $session->value('user')];
      $token= $session->value('token');

      // Refresh claims if necessary, proceed to reauthenticate if that fails.
      try {
        if ($claims && ($result= $this->flow->refresh($claims))) {
          $user= $this->authorize($session, $result);
          $session->transmit($res);
        }
      } catch (Throwable $e) {
        $user= null;
      }
    } else {
      $user= null;
      $token= base64_encode(self::$random->bytes(self::TOKEN_LENGTH));
      $session= $this->sessions->create();
      $session->register('token', $token);
    }

    if (null === $user) {

      // Only start authentication for top-level navigation, issuing 401 errors for
      // sub-requests, e.g. to images or when using fetch from JavaScript to prevent
      // serving non-sensical authentication redirects to these requests.
      if (!in_array($req->header('Sec-Fetch-Mode'), self::IS_NAVIGATION)) {
        $res->answer(401);
        $res->send('Authentication required', 'text/plain');
        return;
      }

      // Authentication may require redirection in order to fulfill its job.
      // In this case, return early from this method w/o passing control on.
      if (null === ($result= $this->flow->authenticate($req, $res, $session))) return;

      // Otherwise, authorize and transmit session
      $user= $this->authorize($session, $result);
      $session->transmit($res);
    }

    return $invocation->proceed($req->pass('user', $user)->pass('token', $token), $res);
  }
}