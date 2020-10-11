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

class CasFlow implements Flow {
  const SESSION_KEY = 'cas::flow';

  /**
   * Creates a new instance with a given SSO base url and sessions implementation
   *
   * @param  string $sso
   * @param  web.auth.cas.URL $url The service URL, uses request URI by default
  */
  public function __construct($sso, URL $url= null) {
    $this->sso= rtrim($sso, '/');
    $this->url= $url ?: new UseRequest();
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

    $uri= $this->url->resolve($request);

    // Validate ticket, then relocate to self without ticket parameter
    if ($ticket= $request->param('ticket')) {
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
      $response->answer(302);
      $response->header('Location', $service->using()->param('_', null)->fragment($request->param('_'), false)->create());
      return null;
    }

    // This is only for test code, real request URIs will never have a fragment
    // as these are a purely client-side concept
    if ($fragment= $uri->fragment()) {
      $uri= $uri->using()->param('_', $fragment)->fragment(null)->create();
    }

    // Send redirect using JavaScript to capture URL fragments.
    //
    // Include meta refresh in body as fallback for when JavaScript is disabled,
    // in which case we lose the fragment, but still offer a degraded service.
    // Do not move this to HTTP headers to ensure the body has been parsed, and
    // the JavaScript executed!
    $target= $this->sso.'/login?service='.urlencode($uri);
    $redirect= sprintf('<!DOCTYPE html>
      <html>
        <head>
          <title>Redirect</title>
          <meta http-equiv="refresh" content="1; URL=%1$s">
        </head>
        <body>
          <script type="text/javascript">
            var hash = document.location.hash.substring(1);
            if (hash) {
              document.location.replace("%1$s" + encodeURIComponent(
                (document.location.search ? "&=" : "?_=") +
                encodeURIComponent(hash)
              ));
            } else {
              document.location.replace("%1$s");
            }
          </script>
        </body>
      </html>',
      $target
    );
    $response->send($redirect, 'text/html');
    return null;
  }
}