<?php namespace web\auth\unittest;

class User {
  private $id, $username;

  /**
   * Creates a new user
   *
   * @param  int $id
   * @param  string $username
   */
  public function __construct($id, $username) {
    $this->id= $id;
    $this->username= $username;
  }

  /** @return int */
  public function id() { return $this->id; }

  /** @return string */
  public function username() { return $this->username; }
}