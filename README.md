Web Authentication
==================

[![Build status on GitHub](https://github.com/xp-forge/web-auth/workflows/Tests/badge.svg)](https://github.com/xp-forge/web-auth/actions)
[![XP Framework Module](https://raw.githubusercontent.com/xp-framework/web/master/static/xp-framework-badge.png)](https://github.com/xp-framework/core)
[![BSD Licence](https://raw.githubusercontent.com/xp-framework/web/master/static/licence-bsd.png)](https://github.com/xp-framework/core/blob/master/LICENCE.md)
[![Requires PHP 7.4+](https://raw.githubusercontent.com/xp-framework/web/master/static/php-7_4plus.svg)](http://php.net/)
[![Supports PHP 8.0+](https://raw.githubusercontent.com/xp-framework/web/master/static/php-8_0plus.svg)](http://php.net/)
[![Latest Stable Version](https://poser.pugx.org/xp-forge/web-auth/version.svg)](https://packagist.org/packages/xp-forge/web-auth)

Authentication for web services. Supports authenticating URLs with fragments such as `https://example.com/#/users/thekid` without losing information when redirecting.

☑ Verified with Twitter (OAuth 1), Microsoft Office 365, Facebook, GitHub and LinkedIn (OAuth 2).

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
  $res->send('Hello @'.$req->value('user')['id'], 'text/plain');
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
$auth= new SessionBased(
  $flow,
  new ForTesting(),
  $flow->fetchUser('https://api.twitter.com/1.1/account/verify_credentials.json')
);

return ['/' => $auth->required(function($req, $res) {
  $res->send('Hello @'.$req->value('user')['screen_name'], 'text/plain');
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
$auth= new SessionBased(
  $flow,
  new ForTesting(),
  $flow->fetchUser('https://api.github.com/user')
);

return ['/' => $auth->required(function($req, $res) {
  $res->send('Hello @'.$req->value('user')['login'], 'text/plain');
})];
```

*The $callback parameter should be the path matching the path in the callback URI registered with GitHub.*

### Authentication via Google:

```php
use web\auth\SessionBased;
use web\auth\oauth\OAuth2Flow;
use web\session\ForTesting;

$flow= new OAuth2Flow(
  'https://accounts.google.com/o/oauth2/v2/auth',
  'https://oauth2.googleapis.com/token',
  [$credentials->named('google_oauth_key'), $credentials->named('google_oauth_secret')],
  $callback,
  ['https://www.googleapis.com/auth/userinfo.profile']
);
$auth= new SessionBased(
  $flow,
  new ForTesting(),
  $flow->fetchUser('https://openidconnect.googleapis.com/v1/userinfo')
);

return ['/' => $auth->required(function($req, $res) {
  $res->send('Hello @'.$req->value('user')['name'], 'text/plain');
})];
```

*The $callback parameter should be the path matching the path in the callback URI registered with GitHub.*

### Authentication via Office 365 Azure AD:

```php
use util\Secret;
use web\auth\SessionBased;
use web\auth\oauth\{OAuth2Flow, BySecret, ByCertificate};
use web\session\ForTesting;

// Depending on what you have set up under "Certificates & Secrets", use one
// of the following. For certificate-based authentication, $privateKey can
// hold either the key's contents or reference it as 'file://private.key'
$credentials= new BySecret('[APP-ID]', new Secret('...'));
$credentials= new ByCertificate('[APP-ID]', '[THUMBPRINT]', $privateKey);

$flow= new OAuth2Flow(
  'https://login.microsoftonline.com/[TENANT_ID]/oauth2/v2.0/authorize',
  'https://login.microsoftonline.com/[TENANT_ID]/oauth2/v2.0/token',
  $credentials,
  $callback,
  ['openid', 'profile', 'offline_access', 'User.Read']
);
$auth= new SessionBased(
  $flow,
  new ForTesting(),
  $flow->fetchUser('https://graph.microsoft.com/v1.0/me')
);

return ['/' => $auth->required(function($req, $res) {
  $res->send('Hello @'.$req->value('user')['login'], 'text/plain');
})];
```

*The $callback parameter should be the path matching the path in the callback URI registered with the Azure AD application.*

### Authentication via [CAS](https://apereo.github.io/cas) ("Central Authentication Service"):

```php
use web\auth\SessionBased;
use web\auth\cas\CasFlow;
use web\session\ForTesting;

$flow= new CasFlow('https://sso.example.com/');
$auth= new SessionBased($flow, new ForTesting());

return ['/' => $auth->required(function($req, $res) {
  $res->send('Hello @'.$req->value('user')['username'], 'text/plain');
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