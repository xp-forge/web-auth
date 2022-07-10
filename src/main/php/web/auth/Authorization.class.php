<?php namespace web\auth;

/** Returned by Flow instances */
abstract class Authorization {
  
  /**
   * Returns claims for this authorization.
   *
   * @return  ?[:var]
   */
  public function claims() { return null; }

}