<?php namespace web\auth\unittest;

use test\{Assert, Test, Values};
use util\URI;
use web\auth\{Flow, UseRequest, UseURL};

class FlowClassTest {
  const URL= 'https://example.com';

  /** Creates a new fixture */
  private function fixture() {
    return new class() extends Flow {

      public function authenticate($request, $response, $session) {
        // Not implemented
      }
    };
  }

  /** @return iterable */
  private function targets() {
    yield [new UseRequest()];
    yield [new UseURL(self::URL)];
  }

  #[Test]
  public function no_namespace() {
    Assert::null($this->fixture()->namespace);
  }

  #[Test]
  public function namespaced() {
    Assert::equals('test', $this->fixture()->namespaced('test')->namespace);
  }

  #[Test]
  public function no_default() {
    Assert::null($this->fixture()->url());
  }

  #[Test]
  public function uses_request_by_default() {
    Assert::instance(UseRequest::class, $this->fixture()->url(true));
  }

  #[Test, Values(from: 'targets')]
  public function target($use) {
    Assert::equals($use, $this->fixture()->target($use)->url());
  }

  #[Test]
  public function target_string() {
    Assert::equals(new UseURL(self::URL), $this->fixture()->target(self::URL)->url());
  }

  #[Test]
  public function no_fragment() {
    Assert::equals(new URI(self::URL), $this->fixture()->service(new URI(self::URL)));
  }

  #[Test]
  public function with_fragment() {
    Assert::equals(
      new URI(self::URL.'?_=capabilities'),
      $this->fixture()->service(new URI(self::URL.'#capabilities'))
    );
  }

  #[Test]
  public function with_params_and_fragment() {
    Assert::equals(
      new URI(self::URL.'?test=ok&_=capabilities'),
      $this->fixture()->service(new URI(self::URL.'?test=ok#capabilities'))
    );
  }
}