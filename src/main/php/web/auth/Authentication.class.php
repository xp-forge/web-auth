<?php namespace web\auth;

use web\{Filter, Filters};

abstract class Authentication implements Filter {

  /**
   * Require authentication for a given handler
   *
   * @param  web.Handler|function(web.Request, web.Response): var $handler
   * @return web.Handler
   */
  public function required($handler) {
    return new Filters([$this], $handler);
  }
}