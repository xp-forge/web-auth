<?php namespace web\auth;

abstract class Context {

  /** Logs out the user. Always returns true */
  public abstract function logout(): bool;
}