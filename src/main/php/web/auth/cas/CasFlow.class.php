<?php namespace web\auth\cas;

use lang\Throwable;
use peer\http\HttpConnection;
use util\Objects;
use util\address\{XmlStreaming, ValueOf};
use web\auth\Flow;
use web\{Cookie, Error, Filter};

class CasFlow extends Flow {
  const SESSION_KEY = 'cas::flow';

  private $sso;

  /**
   * Creates a new instance with a given SSO base url
   *
   * @param  string $sso
   */
  public function __construct($sso) {
    $this->sso= rtrim($sso, '/');
  }

  /**
   * Validates a CAS ticket
   *
   * @param  string $ticket
   * @param  string $service
   * @return peer.http.HttpResponse
   */
  protected function validate($ticket, $service) {
    return (new HttpConnection($this->sso.'/serviceValidate'))->get([
      'ticket'  => $ticket,
      'service' => $service
    ]);
  }

  /**
   * Executes authentication flow, returning the authentication result
   *
   * @param  web.Request $request
   * @param  web.Response $response
   * @param  web.session.Session $session
   * @return var
   */
  public function authenticate($request, $response, $session) {
    $state= $session->value(self::SESSION_KEY);
    if (isset($state['username'])) return $state;

    // If no ticket is present, redirect to SSO. Otherwise, validate ticket,
    // then finalize this flow by relocating to self without ticket parameter.
    $uri= $this->url(true)->resolve($request);
    if (null === ($ticket= $request->param('ticket'))) {
      $target= $this->sso.'/login?service='.urlencode($this->service($uri));

      // If a URL fragment is present, append it to the service parameter (and
      // make sure it's properly encoded!)
      $this->redirect($response, $target, sprintf('
        var hash = document.location.hash.substring(1);
        if (hash) {
          document.location.replace("%1$s" + encodeURIComponent(
            (document.location.search ? "&%2$s=" : "?%2$s=") +
            encodeURIComponent(hash)
          ));
        } else {
          document.location.replace("%1$s");
        }',
        $target,
        self::FRAGMENT
      ));
      return null;
    }

    $service= $uri->using()->param('ticket', null)->create();
    $validate= $this->validate($ticket, $service);
    if (200 !== $validate->statusCode()) {
      throw new Error($validate->statusCode(), $validate->message());
    }

    try {
      $stream= new XmlStreaming($validate->in());
      $result= $stream->next(new ValueOf([], [
        'cas:authenticationFailure' => function(&$self) {
          $self['failure']= yield new ValueOf([], [
            '@code' => function(&$self) { $self['code']= yield; },
            '.'     => function(&$self) { $self['message']= trim(yield); },
          ]);
        },
        'cas:authenticationSuccess' => function(&$self) {
          $self['user']= yield new ValueOf([], [
            'cas:user'       => function(&$self) { $self['username']= yield; },
            'cas:attributes' => function(&$self) {
              $self+= yield new ValueOf([], ['*' => function(&$self, $name) {
                $self[str_replace('cas:', '', $name)]= yield;
              }]);
            },
          ]);
        },
        '*' => function(&$self, $name) { $self[$name]= yield; },
      ]));
    } catch (Throwable $e) {
      throw new Error(500, 'UNEXPECTED: Streaming error', $e);
    }

    // Success-oriented
    if ($user= $result['user'] ?? null) {
      $session->register(self::SESSION_KEY, $user);
      $session->transmit($response);
      $this->finalize($response, $service);
      return null;
    }

    if ($failure= $result['failure'] ?? null) {
      throw new Error(500, $result['failure']['code'].': '.$result['failure']['message']);
    }

    throw new Error(500, 'UNEXPECTED: '.Objects::stringOf($result));
  }
}