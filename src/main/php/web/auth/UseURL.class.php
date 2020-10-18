<?php namespace web\auth;

use util\URI;

/**
 * Uses given URI as service base URL
 */
class UseURL implements URL {
  private $uri;

  /** @param util.URI|string $uri */
  public function __construct($uri) {
    $this->uri= $uri instanceof URI ? $uri : new URI($uri);
  }
  
  /**
   * Resolves URI
   *
   * @param  web.Request $request
   * @return util.URI
   */
  public function resolve($request) {
    return $this->uri->using()
      ->path(rtrim($this->uri->path(), '/').$request->uri()->path())
      ->query($request->uri()->query())
      ->fragment($request->uri()->fragment(), false)
      ->create()
    ;
  }
}