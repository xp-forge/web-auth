<?php namespace web\auth\oauth\unittest;

use io\streams\MemoryInputStream;
use io\streams\Streams;
use lang\FormatException;
use peer\http\HttpResponse;
use unittest\TestCase;
use web\auth\oauth\Response;

class ResponseTest extends TestCase {

  /** Returns a HTTP response from given headers and body with a 200 status code */
  private function response($headers= '', $body= '') {
    return new Response(new HttpResponse(new MemoryInputStream("HTTP/1.1 200 OK\r\n".$headers."\r\n".$body)));
  }

  #[@test]
  public function can_create() {
    $this->response();
  }

  #[@test]
  public function status() {
    $this->assertEquals(200, $this->response()->status());
  }

  #[@test]
  public function empty_headers() {
    $this->assertEquals([], $this->response()->headers());
  }

  #[@test]
  public function headers() {
    $fixture= $this->response("Content-Type: text/html\r\n\r\n");
    $this->assertEquals(['Content-Type' => 'text/html'], $fixture->headers());
  }

  #[@test]
  public function header() {
    $fixture= $this->response("Content-Type: text/html\r\n\r\n");
    $this->assertEquals('text/html', $fixture->header('Content-Type'));
  }

  #[@test]
  public function non_existant_header() {
    $fixture= $this->response();
    $this->assertNull($fixture->header('Content-Type'));
  }

  #[@test]
  public function text_value() {
    $fixture= $this->response("Content-Type: text/plain\r\nContent-Length: 4\r\n", 'Test');
    $this->assertEquals('Test', $fixture->value());
  }

  #[@test, @values(['application/json', 'application/vnd.api+json', 'application/vnd.github.v3+json'])]
  public function json_value($mime) {
    $fixture= $this->response("Content-Type: $mime\r\nContent-Length: 6\r\n", '"Test"');
    $this->assertEquals('Test', $fixture->value());
  }

  #[@test]
  public function form_encoded_value() {
    $fixture= $this->response("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 8\r\n", 'key=Test');
    $this->assertEquals(['key' => 'Test'], $fixture->value());
  }

  #[@test, @expect(['class' => FormatException::class, 'withMessage' => 'Cannot convert content without a mime type to a value'])]
  public function cannot_convert_unknown_to_value() {
    $this->response("Content-Length: 3\r\n", '...')->value();
  }

  #[@test, @expect(['class' => FormatException::class, 'withMessage' => 'Cannot convert "text/html" to a value'])]
  public function cannot_convert_html_to_value() {
    $this->response("Content-Type: text/html\r\nContent-Length: 9\r\n", '<html>...')->value();
  }

  #[@test]
  public function stream() {
    $fixture= $this->response("Content-Type: text/plain\r\nContent-Length: 4\r\n", 'Test');
    $this->assertEquals('Test', Streams::readAll($fixture->stream()));
  }
}