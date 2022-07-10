<?php namespace web\auth;

use util\URI;

abstract class Flow {
  const FRAGMENT = '_';

  private $url= null;

  /**
   * Targets a given URL
   *
   * @param  web.auth.URL $url
   * @return self
   */
  public function target(URL $url) {
    $this->url= $url;
    return $this;
  }

  /**
   * Returns URL
   *
   * @param  bool $default
   * @return ?web.auth.URL
   */
  public function url($default= false): URL {
    return $this->url ?? ($default ? $this->url= new UseRequest() : null);
  }

  /**
   * Replaces fragment by special parameter. This is really only for test
   * code, real request URIs will never have a fragment as these are a
   * purely client-side concept
   *
   * @param  util.URI $service
   * @return util.URI
   */
  protected function service($service) {
    if ($fragment= $service->fragment()) {
      return $service->using()->param(self::FRAGMENT, $fragment)->fragment(null)->create();
    } else {
      return $service;
    }
  }

  /**
   * Perfoms redirection by rendering an HTML page with a given script on it. This
   * is so that sites using URLs like `/#/users/123` will not redirect to "/" when
   * requiring authentication.
   *
   * Includes a meta refresh in head as fallback for when JavaScript is disabled,
   * in which case we lose the fragment, but still offer a degraded service.
   *
   * @param  web.Response $response
   * @param  string|util.URI $target
   * @param  string $script
   * @return void
   */
  protected function redirect($response, $target, $script) {
    $redirect= sprintf('<!DOCTYPE html>
      <html>
        <head>
          <title>Redirect</title>
          <noscript><meta http-equiv="refresh" content="0; URL=%1$s"></noscript>
        </head>
        <body>
          <script type="text/javascript">%2$s</script>
        </body>
      </html>',
      $target,
      $script
    );
    $response->send($redirect, 'text/html');
  }

  /**
   * Final redirect, replacing `_` parameter back with fragment if present
   *
   * @param  web.Response $response
   * @param  string|util.URI $target
   * @return void
   */
  protected function finalize($response, $target) {
    $uri= $target instanceof URI ? $target : new URI($target);

    $response->answer(302);
    $response->header('Location', ($fragment= $uri->param(self::FRAGMENT))
      ? $uri->using()->param(self::FRAGMENT, null)->fragment($fragment, false)->create()
      : $uri
    );
  }

  /**
   * Refreshes access token given a refresh token if necessary.
   *
   * @param  [:var] $claims
   * @return ?web.auth.Authorization
   * @throws lang.IllegalStateException
   */
  public function refresh(array $claims) { return null; }

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