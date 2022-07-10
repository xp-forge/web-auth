<?php namespace web\auth;

/** Returned by Flow instances */
abstract class Authorization {
  
  /**
   * Returns a refreshable authorization - or NULL, if this authorization
   * does not expire (the default in this implementation).
   *
   * @return  ?[:var]
   */
  public function refreshable() { return null; }

}