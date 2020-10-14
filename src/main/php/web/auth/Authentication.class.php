<?php namespace web\auth;

use web\{Filter, Filters};

abstract class Authentication implements Filter {

  /**
   * Require authentication and pass user to a given handler
   *
   * @param  web.Handler|function(web.Request, web.Response): var $handler
   * @return web.Handler
   */
  public function required($handler) {
    return new Filters([$this], $handler);
  }

  /**
   * If present, authenticate and pass user to the given handler
   *
   * @param  web.Handler|function(web.Request, web.Response): var $handler
   * @return web.Handler
   */
  public function optional($handler) {
    $self= $this;
    $filter= function($req, $res, $invocation) use($self) {
      if ($self->present($req)) {
        return $self->filter($req, $res, $invocation);
      } else {
        return $invocation->proceed($req, $res);
      }
    };
    return new Filters([$filter], $handler);
  }
}