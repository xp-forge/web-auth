<?php namespace web\auth\oauth;

interface Client {

  public function fetch($url, $params= []);
}