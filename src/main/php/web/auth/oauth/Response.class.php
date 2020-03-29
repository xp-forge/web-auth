<?php namespace web\auth\oauth;

use io\streams\Streams;
use lang\FormatException;
use peer\http\HttpResponse;
use text\json\Json;
use text\json\StreamInput;

/**
 * Wraps a HTTP response
 *
 * @test  xp://web.auth.oauth.unittest.ResponseTest
 */
class Response {
  private $wrapped;

  public function __construct(HttpResponse $wrapped) {
    $this->wrapped= $wrapped;
  }

  /**
   * Returns the HTTP status code
   *
   * @return int
   */
  public function status() {
    return $this->wrapped->statusCode();
  }

  /**
   * Returns a specific header, or NULL if the header did not exist
   *
   * @param  string $name
   * @return var
   */
  public function header($name) {
    $result= $this->wrapped->header($name);
    if (empty($result)) {
      return null;
    } else if (1 === sizeof($result)) {
      return $result[0];
    } else {
      return $result;
    }
  }

  /**
   * Returns all headers from the response
   *
   * @return [:var]
   */
  public function headers() {
    $result= [];
    foreach ($this->wrapped->headers() as $name => $value) {
      $result[$name]= 1 === sizeof($value) ? $value[0] : $value;
    }
    return $result;
  }

  /**
   * Returns value, deserializing JSON, form-encoded and plaintext responses
   *
   * @return var
   * @throws lang.FormatException if format cannot be converted to a value
   */
  public function value() {
    $type= $this->wrapped->header('Content-Type');
    if (empty($type)) {
      throw new FormatException('Cannot convert content without a mime type to a value');
    }

    $mime= substr($type[0], 0, strcspn($type[0], ';'));
    if ('application/x-www-form-urlencoded' === $mime) {
      parse_str(Streams::readAll($this->wrapped->in()), $value);
      return $value;
    } else if ('text/plain' === $mime) {
      return Streams::readAll($this->wrapped->in());
    } else if ('application/json' === $mime || preg_match('/^application\/vnd\.(.+)\+json$/', $mime)) {
      return Json::read(new StreamInput($this->wrapped->in()));
    } else {
      throw new FormatException('Cannot convert "'.$type[0].'" to a value');
    }
  }

  /**
   * Returns a stream
   *
   * @return io.streams.InputStream
   */
  public function stream() {
    return $this->wrapped->in();
  }
}
