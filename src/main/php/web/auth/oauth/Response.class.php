<?php namespace web\auth\oauth;

use peer\http\HttpResponse;
use text\json\Json;
use text\json\StreamInput;

class Response {
  private $wrapped;

  public function __construct(HttpResponse $wrapped) {
    $this->wrapped= $wrapped;
  }

  public function status() {
    return $this->wrapped->statusCode();
  }

  public function json() {
    return Json::read(new StreamInput($this->wrapped->in()));
  }
}
