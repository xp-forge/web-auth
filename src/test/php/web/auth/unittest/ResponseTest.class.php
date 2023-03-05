<?php namespace web\auth\unittest;

use io\streams\{MemoryInputStream, Streams};
use lang\FormatException;
use peer\http\HttpResponse;
use test\Assert;
use test\{Expect, Test, TestCase, Values};
use web\auth\oauth\Response;

class ResponseTest {

  /** Returns a HTTP response from given headers and body with a 200 status code */
  private function response($headers= '', $body= '') {
    return new Response(new HttpResponse(new MemoryInputStream("HTTP/1.1 200 OK\r\n".$headers."\r\n".$body)));
  }

  #[Test]
  public function can_create() {
    $this->response();
  }

  #[Test]
  public function status() {
    Assert::equals(200, $this->response()->status());
  }

  #[Test]
  public function empty_headers() {
    Assert::equals([], $this->response()->headers());
  }

  #[Test]
  public function headers() {
    $fixture= $this->response("Content-Type: text/html\r\n\r\n");
    Assert::equals(['Content-Type' => 'text/html'], $fixture->headers());
  }

  #[Test]
  public function header() {
    $fixture= $this->response("Content-Type: text/html\r\n\r\n");
    Assert::equals('text/html', $fixture->header('Content-Type'));
  }

  #[Test]
  public function non_existant_header() {
    $fixture= $this->response();
    Assert::null($fixture->header('Content-Type'));
  }

  #[Test]
  public function text_value() {
    $fixture= $this->response("Content-Type: text/plain\r\nContent-Length: 4\r\n", 'Test');
    Assert::equals('Test', $fixture->value());
  }

  #[Test, Values(['application/json', 'application/vnd.api+json', 'application/vnd.github.v3+json'])]
  public function json_value($mime) {
    $fixture= $this->response("Content-Type: $mime\r\nContent-Length: 6\r\n", '"Test"');
    Assert::equals('Test', $fixture->value());
  }

  #[Test]
  public function form_encoded_value() {
    $fixture= $this->response("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 8\r\n", 'key=Test');
    Assert::equals(['key' => 'Test'], $fixture->value());
  }

  #[Test, Expect(class: FormatException::class, message: 'Cannot convert content without a mime type to a value')]
  public function cannot_convert_unknown_to_value() {
    $this->response("Content-Length: 3\r\n", '...')->value();
  }

  #[Test, Expect(class: FormatException::class, message: 'Cannot convert "text/html" to a value')]
  public function cannot_convert_html_to_value() {
    $this->response("Content-Type: text/html\r\nContent-Length: 9\r\n", '<html>...')->value();
  }

  #[Test]
  public function stream() {
    $fixture= $this->response("Content-Type: text/plain\r\nContent-Length: 4\r\n", 'Test');
    Assert::equals('Test', Streams::readAll($fixture->stream()));
  }
}