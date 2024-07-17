Web Authentication change log
=============================

## ?.?.? / ????-??-??

* Merged PR #30: Make it possible to change the session namespace (OAuth)
  (@thekid)

## 5.1.0 / 2024-04-08

* Merged PR #29: Make callback and scopes mutable - @thekid

## 5.0.0 / 2024-03-29

* Dropped support for PHP 7.0 - 7.3, step 1 of xp-framework/rfc#343
  (@thekid)
* Merged PR #28: Refactor CAS authentication flow to use address library
  (@thekid)

## 4.2.0 / 2024-03-29

* Made compatible with `xp-framework/xml` 12.0+ - @thekid

## 4.1.0 / 2024-03-24

* Made compatible with XP 12 - @thekid

## 4.0.0 / 2024-02-04

* Implemented xp-framework/rfc#341: Drop XP <= 9 compatibility - @thekid
* **Heads up**: Removed deprecated *Token* class which has been replaced
  by `web.auth.oauth.BySecret`
  (@thekid)

## 3.8.0 / 2024-01-30

* Added PHP 8.4 to the test matrix - @thekid
* Made this library compatible with xp-forge/web version 4.0 - @thekid

## 3.7.0 / 2024-01-01

* Merged PR #27: Add `UserInfo` to map the returned user from a flow
  (@thekid)

## 3.6.0 / 2023-07-10

* Merged PR #25: Extract OAuth 2 backend interaction into dedicated class
  (@thekid)

## 3.5.0 / 2023-07-02

* Merged PR #24: Implement certificate-based OAuth2 flow - @thekid
* Merged PR #23: Migrate to new testing library - @thekid

## 3.4.1 / 2022-11-23

* Merged PR #21: Reuse state when previous redirect was incomplete, see
  also #19 ("Flow error")
  (@thekid)

## 3.4.0 / 2022-07-10

* Merged PR #18: Automatically refresh OAuth2 tokens - @thekid

## 3.3.0 / 2022-07-10

* Made compatible with `xp-forge/sessions` version 3.0 - @thekid

## 3.2.0 / 2022-07-09

* Merged PR #15: Add OAuth2Flow::refresh() - which uses `refresh_token`
  to create a new access token
  (@thekid)
* Fixed session potentially being transmitted twice when completing an
  authentication flow.
  (@thekid)

## 3.1.1 / 2022-02-26

* Fixed "Creation of dynamic property" warnings in PHP 8.2 - @thekid

## 3.1.0 / 2021-11-10

* Merged PR #14: Store "id_token" if returned from OAuth token endpoint
  (@thekid)

## 3.0.2 / 2021-10-21

* Made library compatible with XP 11, `xp-framework/xml` version 11.0.0
  and `xp-forge/json` version 5.0.0
  (@thekid)

## 3.0.1 / 2021-09-26

* Made compatible with XP web 3.0, see xp-forge/web#83 - @thekid

## 3.0.0 / 2021-05-14

* Merged PR #13: Create random token, store in session and pass to request.
  **Heads up:** Submitting forms without CSRF tokens will result in a `400`
  error being displayed!
  (@thekid)

## 2.2.2 / 2021-03-14

* Fixed issue #10: Undefined array key "token_type" when response value
  does not contain this key. The spec clearly states this is REQUIRED
  (https://tools.ietf.org/html/rfc6749#section-5.1), some implementations
  do not return this nevertheless. Default to `Bearer` in this case.
  (@thekid)

## 2.2.1 / 2021-02-05

* Reset state after authentication via OAuth in order to prevent dead
  ends with expired tokens - instead, authentication will be retried
  (@thekid)

## 2.2.0 / 2021-01-03

* Made it possible to send more than just `GET` requests with `fetch()`
  (@thekid)

## 2.1.0 / 2020-12-26

* **Heads up:** OAuth implementations now require a callback URL. If
  omitted, a deprecation notice will be raised, which will not break
  production code but make unit tests fail.
  (@thekid)
* Merged PR #6: Fix callback URL mismatches, fixing issue #5 - @thekid

## 2.0.1 / 2020-12-23

* Fixed `ISession::transmit()` not being called after authentication
  (@thekid)

## 2.0.0 / 2020-10-18

* Added support for redirecting to URLs with fragments (`/#/users/123`)
  for OAuth1 and OAuth2; previously only CAS flows supported these.
  (@thekid)
* **Heads up**: Refactored `web.auth.Flow` interface to an abstract class
  (@thekid)
* **Heads up**: Refactored `Authentication` to be a base class of the
  two implementations, `web.auth.Basic` and `web.auth.SessionBased`
  (@thekid)
* Merged PR #4: Implement `Authentication::optional()` - @thekid
* Merged PR #3: Implement basic authentication - @thekid
* Merged PR #2: Add `Authentication::required()` method - @thekid

## 1.1.0 / 2020-10-11

* Merged PR #1: Add CAS login flow, supporting CAS protocol version 2.0+,
  see https://apereo.github.io/cas
  (@thekid)

## 1.0.1 / 2020-07-26

* Fixed OAuth flows throwing exceptions when a previous authorization flow
  was not completed successfully. Instead, retry authorization.
  (@thekid)

## 1.0.0 / 2020-04-10

* Implemented xp-framework/rfc#334: Drop PHP 5.6:
  . **Heads up:** Minimum required PHP version now is PHP 7.0.0
  . Rewrote code base, grouping use statements
  (@thekid)

## 0.5.0 / 2020-04-05

* Removed `session_state` parameter for OAuth 2.0 responses. See
  https://stackoverflow.com/questions/24922550/azure-active-directory-session-state
  (@thekid)

## 0.4.0 / 2020-03-29

* Added support for text/plain and application/x-www-form-urlencoded
  values to `Response::value()`
  (@thekid)

## 0.3.0 / 2020-01-12

* Added support for authenticating against Microsoft's Office 365:
  - Added support for JSON responses when fetching OAuth2 tokens
  - Added support for passing scope to OAuth2 flow
  (@thekid)

## 0.2.0 / 2019-12-01

* Updated session library dependency to 1.0 - @thekid

## 0.1.0 / 2019-12-01

* Made compatible with XP 10 - @thekid
* Hello World! First release - @thekid