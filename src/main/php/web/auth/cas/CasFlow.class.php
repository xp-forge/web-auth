<?php namespace web\auth\cas;

use peer\http\HttpConnection;
use web\Cookie;
use web\Error;
use web\Filter;
use web\auth\Flow;
use xml\XMLFormatException;
use xml\dom\Document;
use xml\parser\StreamInputSource;
use xml\parser\XMLParser;

class CasFlow extends Flow {
  const SESSION_KEY = 'cas::flow';

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

    $result= new Document();
    try {
      (new XMLParser())->withCallback($result)->parse(new StreamInputSource($validate->in()));
    } catch (XMLFormatException $e) {
      throw new Error(500, 'FORMAT: Validation cannot be parsed', $e);
    }

    if ($failure= $result->getElementsByTagName('cas:authenticationFailure')) {
      throw new Error(500, $failure[0]->getAttribute('code').': '.trim($failure[0]->getContent()));
    } else if (!($success= $result->getElementsByTagName('cas:authenticationSuccess'))) {
      throw new Error(500, 'UNEXPECTED: '.$result->getSource());
    }

    $user= ['username' => $result->getElementsByTagName('cas:user')[0]->getContent()];
    if ($attr= $result->getElementsByTagName('cas:attributes')) {
      foreach ($attr[0]->getChildren() as $child) {
        $user[str_replace('cas:', '', $child->getName())]= $child->getContent();
      }
    }

    $session->register(self::SESSION_KEY, $user);
    $session->transmit($response);
    $this->finalize($response, $service);
  }
}