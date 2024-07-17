<?php namespace web\auth\oauth;

use util\URI;
use web\auth\{Flow, UserInfo, AuthenticationError};

abstract class OAuthFlow extends Flow {
  protected $callback;

  /** @return ?util.URI */
  public function callback() { return $this->callback; }

  /** @param ?string|util.URI $callback */
  public function calling($callback): self {
    $this->callback= null === $callback || $callback instanceof URI ? $callback : new URI($callback);
    return $this;
  }

  /**
   * Returns user info which fetched from the given endpoint using the
   * authorized OAuth client
   *
   * @param  string|util.URI $endpoint
   * @return web.auth.UserInfo
   */
  public function fetchUser($endpoint= null): UserInfo {
    return new UserInfo(function(Client $client) use($endpoint) {
      $response= $client->fetch((string)$endpoint);
      if ($response->status() >= 400) {
        throw new AuthenticationError('Unexpected status '.$response->status().' from '.$endpoint);
      }
      return $response->value();
    });
  }
}