<?php namespace web\auth;

abstract class Flow {
  const FRAGMENT = '_';

  private $url;

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
   * Send redirect using JavaScript to capture URL fragments. This is so that
   * sites using URLs like `/#/users/123` will not redirect to "/" when requiring
   * authentication. Uses `_` as special parameter name.
   *
   * @param  web.Response $response
   * @param  string|util.URI $target
   * @return void
   */
  protected function login($response, $target) {

    // Include meta refresh in body as fallback for when JavaScript is disabled,
    // in which case we lose the fragment, but still offer a degraded service.
    // Do not move this to HTTP headers to ensure the body has been parsed, and
    // the JavaScript executed!
    $redirect= sprintf('<!DOCTYPE html>
      <html>
        <head>
          <title>Redirect</title>
          <meta http-equiv="refresh" content="1; URL=%1$s">
        </head>
        <body>
          <script type="text/javascript">
            var hash = document.location.hash.substring(1);
            if (hash) {
              document.location.replace("%1$s" + encodeURIComponent(
                (document.location.search ? "&%2$s=" : "?%2$s=") +
                encodeURIComponent(hash)
              ));
            } else {
              document.location.replace("%1$s");
            }
          </script>
        </body>
      </html>',
      $target,
      self::FRAGMENT
    );
    $response->send($redirect, 'text/html');
  }

  /**
   * Final redirect, replacing `_` parameter back with fragment if present
   *
   * @param  web.Response $response
   * @param  util.URI $service
   * @return void
   */
  protected function finalize($response, $service) {
    if ($fragment= $service->param(self::FRAGMENT)) {
      $service= $service->using()->param(self::FRAGMENT, null)->fragment($fragment, false)->create();
    }

    $response->answer(302);
    $response->header('Location', $service);
  }

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