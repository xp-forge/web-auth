Web Authentication
==================

[![Build status on GitHub](https://github.com/xp-forge/web-auth/workflows/Tests/badge.svg)](https://github.com/xp-forge/web-auth/actions)
[![XP Framework Module](https://raw.githubusercontent.com/xp-framework/web/master/static/xp-framework-badge.png)](https://github.com/xp-framework/core)
[![BSD Licence](https://raw.githubusercontent.com/xp-framework/web/master/static/licence-bsd.png)](https://github.com/xp-framework/core/blob/master/LICENCE.md)
[![Requires PHP 7.0+](https://raw.githubusercontent.com/xp-framework/web/master/static/php-7_0plus.svg)](http://php.net/)
[![Supports PHP 8.0+](https://raw.githubusercontent.com/xp-framework/web/master/static/php-8_0plus.svg)](http://php.net/)
[![Latest Stable Version](https://poser.pugx.org/xp-forge/web-auth/version.png)](https://packagist.org/packages/xp-forge/web-auth)

Authentication for web services. Supports authenticating URLs with fragments such as `https://example.com/#/users/thekid` without losing information when redirecting.

☑ Verified with Twitter (OAuth 1), Microsoft Office 365, GitHub and LinkedIn (OAuth 2).

Examples
--------
### HTTP basic authentication:

```php
use web\auth\Basic;
use util\Secret;

$auth= new Basic('Administration', function($user, Secret $secret) {
  return 'admin' === $user && $secret->equals('secret') ? ['id' => 'admin'] : null;
});

return ['/' => $auth->required(function($req, $res) {
  $res->send('Hello @'.$req->value('user')['id'], 'text/html');
})];
```

### Authentication via Twitter:

```php
use web\auth\SessionBased;
use web\auth\oauth\OAuth1Flow;
use web\session\ForTesting;

$flow= new OAuth1Flow(
  'https://api.twitter.com/oauth',
  [$credentials->named('twitter_oauth_key'), $credentials->named('twitter_oauth_secret')],
  $callback
);
$auth= new SessionBased($flow, new ForTesting(), function($client) {
  return $client->fetch('https://api.twitter.com/1.1/account/verify_credentials.json')->value();
});

return ['/' => $auth->required(function($req, $res) {
  $res->send('Hello @'.$req->value('user')['screen_name'], 'text/html');
})];
```

*The $callback parameter should be the path matching the path in the callback URI registered with Twitter.*

### Authentication via GitHub:

```php
use web\auth\SessionBased;
use web\auth\oauth\OAuth2Flow;
use web\session\ForTesting;

$flow= new OAuth2Flow(
  'https://github.com/login/oauth/authorize',
  'https://github.com/login/oauth/access_token',
  [$credentials->named('github_oauth_key'), $credentials->named('github_oauth_secret')],
  $callback
);
$auth= new SessionBased($flow, new ForTesting(), function($client) {
  return $client->fetch('https://api.github.com/user')->value();
});

return ['/' => $auth->required(function($req, $res) {
  $res->send('Hello @'.$req->value('user')['login'], 'text/html');
})];
```

*The $callback parameter should be the path matching the path in the callback URI registered with GitHub.*

### Authentication via [CAS](https://apereo.github.io/cas) ("Central Authentication Service"):

```php
use web\auth\SessionBased;
use web\auth\cas\CasFlow;
use web\session\ForTesting;

$flow= new CasFlow('https://sso.example.com/');
$auth= new SessionBased($flow, new ForTesting());

return ['/' => $auth->required(function($req, $res) {
  $res->send('Hello @'.$req->value('user')['username'], 'text/html');
})];
```

Target URLs
-----------
By default, the flow instances use the request URI to determine where the service is running. Behind a proxy, this is most probably not the user-facing URI. To change this behavior, use the `target()` method and pass a `UseURL` instance as follows:

```php
use web\auth\UseURL;
use web\auth\cas\CasFlow;

$flow= (new CasFlow('https://sso.example.com/'))->target(new UseURL('https://service.example.com/'));
```