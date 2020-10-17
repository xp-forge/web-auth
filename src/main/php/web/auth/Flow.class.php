<?php namespace web\auth;

abstract class Flow {

  /**
   * Executes authentication flow, returning the authentication result
   *
   * @param  web.Request $request
   * @param  web.Response $response
   * @param  web.session.Session $session
   * @return var
   */
  public abstract function authenticate($request, $response, $session);
}