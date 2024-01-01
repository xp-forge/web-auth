<?php namespace web\auth\unittest;

use io\streams\MemoryInputStream;
use peer\http\HttpResponse;
use web\auth\oauth\{Client, Response};

trait Clients {

  /* Returns a client whose `fetch()` operation returns the given response */
  public function responding(int $status, array $headers, string $payload): Client {
    return newinstance(Client::class, [], [
      'authorize' => function($request) { return $request; },
      'token'     => function() { return 'TOKEN'; },
      'fetch'     => function($url, $options= []) use($status, $headers, $payload) {
        $message= "HTTP/1.1 {$status} ...\r\n";
        foreach ($headers + ['Content-Length' => strlen($payload)] as $name => $value) {
          $message.= "{$name}: {$value}\r\n";
        }
        return new Response(new HttpResponse(new MemoryInputStream($message."\r\n".$payload)));
      }
    ]);
  }
}