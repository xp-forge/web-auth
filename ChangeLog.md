Web Authentication change log
=============================

## ?.?.? / ????-??-??

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