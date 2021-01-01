<?php namespace web\auth;

use web\session\Sessions;

class SessionBased extends Authentication {
  private $flow, $sessions, $lookup;

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
    return ($session= $this->sessions->locate($req)) ? null !== $session->value('user') : false;
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
      $user= $session->value('user');
    } else {
      $session= $this->sessions->create();
      $user= null;
    }

    if (null === $user) {
      if (null === ($result= $this->flow->authenticate($req, $res, $session))) return;

      // Optionally map result to a user using lookup, otherwise use result directly
      $user= $this->lookup ? ($this->lookup)($result) : $result;
      $session->register('user', $user);
    }

    try {
      return $invocation->proceed($req->pass('user', $user), $res);
    } finally {
      $session->transmit($res);
    }
  }
}