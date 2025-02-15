<?php namespace web\auth;

use web\session\ISession;
use web\{Request, Response};

class SessionContext extends Context {
  private $session, $request, $response;

  /** Creates a new session context */
  public function __construct(ISession $session, Request $request, Response $response) {
    $this->session= $session;
    $this->request= $request;
    $this->response= $response;
  }

  public function user() {
    return ($this->session->value('auth') ?? [null, $this->session->value('user')])[1];
  }

  public function claims() {
    return ($this->session->value('auth') ?? [null, $this->session->value('user')])[0];
  }

  /** Modifies context with given changes */
  public function modify(iterable $changes): self {
    [$claims, $user]= $this->session->value('auth') ?? [null, $this->session->value('user')];
    foreach ($changes as $key => $value) {
      $user[$key]= $value;
    }

    $this->session->register('auth', [$claims, $user]);
    $this->session->transmit($this->response);
    $this->request->pass('user', $user);
    return $this;
  }

  /** Destroys underlying session, effectively logging out the user */
  public function logout(): bool {
    if ($this->session->valid()) {
      $this->session->destroy();
      $this->session->transmit($this->response);
    }
    return true;
  }
}