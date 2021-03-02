# bpo-23740
Tests and discovery to character `Python http.client.HTTPConnection.send()` behaviour, for https://bugs.python.org/issue13559

## http_dump.py

A webserver (inspired by https://httpbin.org) that returns (raw) headers and body of the request.

For example `curl --upload-file` uses `Transfer-Encoding: chunked`, to `PUT` a file of unknown length.

```
$ curl http://localhost:8000/path --upload-file <(echo foo=bar)
{
  "command": "PUT",
  "path": "/path",
  "version": "HTTP/1.1",
  "headers": [
    [
      "Host",
      "localhost:8000"
    ],
    [
      "User-Agent",
      "curl/7.68.0"
    ],
    [
      "Accept",
      "*/*"
    ],
    [
      "Transfer-Encoding",
      "chunked"
    ],
    [
      "Expect",
      "100-continue"
    ]
  ],
  "content": "foo=bar\n",
  "raw": {
    "requestline": "PUT /path HTTP/1.1\r\n",
    "headers": "Host: localhost:8000\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n",
    "content": "8\r\nfoo=bar\n\r\n0\r\n\r\n"
  }
}
```

## http_tests.py

A script to pump various values into `http.client.HTTPConnection.send()`, results are written to [results/](results/)

```
$ ./http_tests.py
 0. OK  results/bytearray/body.json
 1. OK  results/bytes/body.json
 2. OK  results/io.BytesIO/body.json
 3. OK  results/io.StringIO/body.json
 4. OK  results/Iterable[bytearray]/body.json
 5. OK  results/Iterable[bytes]/body.json
 6. ERR Iterable[str] TypeError("can't concat str to bytes")
 7. OK  results/memoryview/body.json
 8. OK  results/None/body.json
 9. OK  results/obj.read(),mode=r,encoding=utf-8/body.json
10. OK  results/obj.read(),mode=rb/body.json
11. OK  results/obj.read()/body.json
12. OK  results/str/body.json
```
