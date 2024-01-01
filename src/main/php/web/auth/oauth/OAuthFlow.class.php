<?php namespace web\auth\oauth;

use web\auth\{Flow, UserInfo, AuthenticationError};

abstract class OAuthFlow extends Flow {

  /**
   * Returns user info which fetched from the given endpoint using the
   * authorized OAuth2 client
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