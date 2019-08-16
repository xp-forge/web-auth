<?php namespace web\auth\oauth;

interface Session {

  public function fetch($url, $params= []);
}