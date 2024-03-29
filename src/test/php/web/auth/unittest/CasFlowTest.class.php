<?php namespace web\auth\unittest;

use io\streams\MemoryInputStream;
use peer\http\HttpResponse;
use test\Assert;
use test\{Expect, Test, TestCase, Values};
use web\auth\cas\CasFlow;
use web\auth\{UseRequest, UseURL};
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;
use web\{Error, Request, Response};

class CasFlowTest extends FlowTest {
  const SSO     = 'https://example.com/sso';
  const SERVICE = 'https://service.example.com';
  const TICKET  = 'ST-1856339-aA5Yuvrxzpv8Tau1cYQ7';

  /**
   * Asserts a given response redirects to a given SSO login
   *
   * @param  string $service
   * @param  web.Response $res
   * @throws unittest.AssertionFailedError
   */
  private function assertLoginWith($service, $res) {
    Assert::equals(self::SSO.'/login?service='.urlencode($service), $this->redirectTo($res));
  }

  /**
   * Creates a validation response
   *
   * @param  string $xml
   * @return peer.http.HttpResponse
   */
  public static function response($xml) {
    return new HttpResponse(new MemoryInputStream(sprintf(
      "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n%s",
      strlen($xml),
      $xml
    )));
  }

  #[Test]
  public function can_create() {
    new CasFlow(self::SSO);
  }

  #[Test, Values(from: 'paths')]
  public function redirects_to_sso($path) {
    $this->assertLoginWith(
      'http://localhost'.$path,
      $this->authenticate(new CasFlow(self::SSO), $path)
    );
  }

  #[Test, Values(from: 'paths')]
  public function redirects_to_sso_using_request($path) {
    $this->assertLoginWith(
      'http://localhost'.$path,
      $this->authenticate((new CasFlow(self::SSO))->target(new UseRequest()), $path)
    );
  }

  #[Test, Values(from: 'paths')]
  public function redirects_to_sso_given_service($path) {
    $this->assertLoginWith(
      self::SERVICE.$path,
      $this->authenticate((new CasFlow(self::SSO))->target(new UseURL(self::SERVICE)), $path)
    );
  }

  #[Test, Values(from: 'fragments')]
  public function redirects_to_sso_with_fragment_in_special_parameter($fragment) {
    $this->assertLoginWith(
      'http://localhost/?_='.urlencode($fragment),
      $this->authenticate(new CasFlow(self::SSO), '/#'.$fragment)
    );
  }

  #[Test, Values(from: 'fragments')]
  public function redirects_to_sso_with_fragment_in_special_parameter_using_request($fragment) {
    $this->assertLoginWith(
      'http://localhost/?_='.urlencode($fragment),
      $this->authenticate((new CasFlow(self::SSO))->target(new UseRequest()), '/#'.$fragment)
    );
  }

  #[Test, Values(from: 'fragments')]
  public function redirects_to_sso_with_fragment_in_special_parameter_given_service($fragment) {
    $this->assertLoginWith(
      self::SERVICE.'/?_='.urlencode($fragment),
      $this->authenticate((new CasFlow(self::SSO))->target(new UseURL(self::SERVICE)), '/#'.$fragment)
    );
  }

  #[Test, Values(from: 'fragments')]
  public function redirects_to_self_with_fragment_from_special_parameter($fragment) {
    $fixture= new class(self::SSO) extends CasFlow {
      public function validate($ticket, $service) {
        return CasFlowTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
            <cas:authenticationSuccess>
              <cas:user>test</cas:user>
            </cas:authenticationSuccess>
          </cas:serviceResponse>
        ');
      }
    };

    $res= $this->authenticate($fixture, '/?_='.urlencode($fragment).'&ticket='.self::TICKET);
    Assert::equals('http://localhost/#'.$fragment, $res->headers()['Location']);
  }

  #[Test]
  public function validates_ticket_then_redirects_to_self() {
    $fixture= new class(self::SSO) extends CasFlow {
      public function validate($ticket, $service) {
        return CasFlowTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
            <cas:authenticationSuccess>
              <cas:user>test</cas:user>
            </cas:authenticationSuccess>
          </cas:serviceResponse>
        ');
      }
    };

    $res= $this->authenticate($fixture, '/?ticket='.self::TICKET);
    Assert::equals('http://localhost/', $res->headers()['Location']);
  }

  #[Test]
  public function stores_user_in_session() {
    $fixture= new class(self::SSO) extends CasFlow {
      public function validate($ticket, $service) {
        return CasFlowTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
            <cas:authenticationSuccess>
              <cas:user>test</cas:user>
            </cas:authenticationSuccess>
          </cas:serviceResponse>
        ');
      }
    };
    $session= (new ForTesting())->create();

    $this->authenticate($fixture, '/?ticket='.self::TICKET, $session);
    Assert::equals(
      ['username' => 'test'],
      $session->value(CasFlow::SESSION_KEY)
    );
  }

  #[Test]
  public function stores_additional_user_attributes_in_session() {
    $fixture= new class(self::SSO) extends CasFlow {
      public function validate($ticket, $service) {
        return CasFlowTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
            <cas:authenticationSuccess>
              <cas:user>test</cas:user>
              <cas:attributes>
                <cas:givenName>John Doe</cas:givenName>
                <cas:email>jdoe@example.org</cas:email>
              </cas:attributes>
            </cas:authenticationSuccess>
          </cas:serviceResponse>
        ');
      }
    };
    $session= (new ForTesting())->create();

    $this->authenticate($fixture, '/?ticket='.self::TICKET, $session);
    Assert::equals(
      ['username' => 'test', 'givenName' => 'John Doe', 'email' => 'jdoe@example.org'],
      $session->value(CasFlow::SESSION_KEY)
    );
  }

  #[Test]
  public function returns_user_in_final_step() {
    $user= ['username' => 'test'];

    $fixture= new CasFlow(self::SSO);
    $session= (new ForTesting())->create();
    $session->register(CasFlow::SESSION_KEY, $user);

    $req= new Request(new TestInput('GET', '/'));
    $res= new Response(new TestOutput());
    $result= $fixture->authenticate($req, $res, $session);

    Assert::equals($user, $result);
  }

  #[Test, Expect(class: Error::class, message: '/INVALID_TICKET: Ticket .+ not recognized/')]
  public function shows_error_when_ticket_cannot_be_validated() {
    $fixture= new class(self::SSO) extends CasFlow {
      public function validate($ticket, $service) {
        return CasFlowTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
            <cas:authenticationFailure code="INVALID_TICKET">
              Ticket ST-1856339-aA5Yuvrxzpv8Tau1cYQ7 not recognized`
            </cas:authenticationFailure>
          </cas:serviceResponse>
        ');
      }
    };

    $this->authenticate($fixture, '/?ticket='.self::TICKET);
  }

  #[Test, Expect(class: Error::class, message: '/UNEXPECTED: .+/')]
  public function shows_error_when_validation_response_invalid() {
    $fixture= new class(self::SSO) extends CasFlow {
      public function validate($ticket, $service) {
        return CasFlowTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
            <!-- Empty -->
          </cas:serviceResponse>
        ');
      }
    };

    $this->authenticate($fixture, '/?ticket='.self::TICKET);
  }

  #[Test, Expect(class: Error::class, message: 'UNEXPECTED: []')]
  public function shows_error_when_validation_response_not_well_formed() {
    $fixture= new class(self::SSO) extends CasFlow {
      public function validate($ticket, $service) {
        return CasFlowTest::response('
          <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
          </cas:NOT_WELL_FORMED>
        ');
      }
    };

    $this->authenticate($fixture, '/?ticket='.self::TICKET);
  }
}