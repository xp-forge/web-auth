<?php namespace web\auth\unittest;

use test\AssertionFailedError;
use web\io\{TestInput, TestOutput};
use web\session\ForTesting;
use web\{Request, Response};

abstract class FlowTest {

  /** @return iterable */
  protected function paths() {
    yield ['/'];
    yield ['/home'];
    yield ['/~test'];
    yield ['/?a=b'];
    yield ['/?a=b&c=d'];
  }

  /** @return iterable */
  protected function fragments() {
    yield ['top'];
    yield ['/users/~test'];
  }

  /**
   * Calls authenticate method, returning response
   * 
   * @param  web.auth.Flow $fixture
   * @param  string $path
   * @param  web.session.ISession $session
   * @return web.Response
   */
  protected function authenticate($fixture, $path= '/', $session= null) {
    $req= new Request(new TestInput('GET', $path));
    $res= new Response(new TestOutput());
    $fixture->authenticate($req, $res, $session ?? (new ForTesting())->create());
    return $res;
  }

  /**
   * Returns URL from initial login redirect
   *
   * @param  web.Response $response
   * @return string
   * @throws unittest.AssertionFailedError
   */
  protected function redirectTo($res) {
    $bytes= $res->output()->bytes();
    if (preg_match('/<meta http-equiv="refresh" content="[0-9]+; URL=([^"]+)">/', $bytes, $m)) {
      return $m[1];
    }
    throw new AssertionFailedError('No redirect URL in response `'.$bytes.'`');
  }
}