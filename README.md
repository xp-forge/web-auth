Web Authentication
==================

[![Build Status on TravisCI](https://secure.travis-ci.org/xp-forge/web-auth.svg)](http://travis-ci.org/xp-forge/web-auth)
[![XP Framework Module](https://raw.githubusercontent.com/xp-framework/web/master/static/xp-framework-badge.png)](https://github.com/xp-framework/core)
[![BSD Licence](https://raw.githubusercontent.com/xp-framework/web/master/static/licence-bsd.png)](https://github.com/xp-framework/core/blob/master/LICENCE.md)
[![Requires PHP 7.0+](https://raw.githubusercontent.com/xp-framework/web/master/static/php-7_0plus.png)](http://php.net/)
[![Latest Stable Version](https://poser.pugx.org/xp-forge/web-auth/version.png)](https://packagist.org/packages/xp-forge/web-auth)

Authentication for web services. Uses sessions to store authentication information.

Examples
--------
HTTP basic authentication:

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

Authentication via Twitter:

```php
use web\auth\SessionBased;
use web\auth\oauth\OAuth1Flow;
use web\session\ForTesting;

$flow= new OAuth1Flow('https://api.twitter.com/oauth', [
  $credentials->named('twitter_oauth_key'),
  $credentials->named('twitter_oauth_secret'),
]);
$auth= new SessionBased($flow, new ForTesting(), function($client) {
  return $client->fetch('https://api.twitter.com/1.1/account/verify_credentials.json')->value();
});

return ['/' => $auth->required(function($req, $res) {
  $res->send('Hello @'.$req->value('user')['screen_name'], 'text/html');
})];
```

Authentication via GitHub:

```php
use web\auth\SessionBased;
use web\auth\oauth\OAuth2Flow;
use web\session\ForTesting;

$flow= new OAuth2Flow(
  'https://github.com/login/oauth/authorize',
  'https://github.com/login/oauth/access_token',
  [$credentials->named('github_oauth_key'), $credentials->named('github_oauth_secret')],
);
$auth= new SessionBased($flow, new ForTesting(), function($client) {
  return $client->fetch('https://api.github.com/user')->value();
});

return ['/' => $auth->required(function($req, $res) {
  $res->send('Hello @'.$req->value('user')['login'], 'text/html');
})];
```

Authentication via [CAS](https://apereo.github.io/cas) ("Central Authentication Service"):

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