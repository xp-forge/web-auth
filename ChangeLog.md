Web Authentication change log
=============================

## ?.?.? / ????-??-??

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