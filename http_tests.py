#!/usr/bin/env python3
"""
Submit http requests with different types supplied as the content
"""

import argparse
import http.client
import io
import os
import pathlib
import sys
import urllib.parse


HERE = pathlib.Path(__file__).parent


class Readable:
    def __init__(self, fp):
        self.fp = fp

    def read(self, size=None):
        return self.fp.read(size)



TEST_CASES = {
    'bytearray': bytearray(b'abc\r\ndef\r\n'),
    'bytes': b'abc\r\ndef\r\n',
    'io.BytesIO': io.BytesIO(b'abc\r\ndef\r\n'),
    'io.StringIO': io.StringIO('abc\r\ndef\r\n'),
    'Iterable[bytearray]': (bytearray(s) for s in [b'abc\r\n', b'def\r\n']),
    'Iterable[bytes]': (s for s in [b'abc\r\n', b'def\r\n']),
    'Iterable[str]': (s for s in ['abc\r\n', 'def\r\n']),
    'memoryview': memoryview(b'abc\r\ndef\r\n'),
    'None': None,
    'obj.read(),mode=r,encoding=utf-8': open(HERE/'files/crlf/ascii.txt', mode='r', encoding='utf-8'),
    'obj.read(),mode=rb': open(HERE/'files/crlf/ascii.txt', mode='rb'),
    'obj.read()': Readable(io.BytesIO(b'abc\r\ndef\r\n')),
    'str': 'abc\r\ndef\r\n',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',
                        type=urllib.parse.urlparse,
                        default='http://localhost:8000')
    parser.add_argument('--results-base', metavar='PATH',
                        type=pathlib.Path,
                        default='results')
    args = parser.parse_args()

    for i, (name, body) in enumerate(TEST_CASES.items()):
        results_file = args.results_base / name / 'body.json'
        conn = http.client.HTTPConnection(args.url.netloc)

        try:
            conn.request('PUT', f'/path/{i}', body)
        except Exception as err:
            print(f'{i:>2}. ERR {name} {err!r}')
            continue
        else:
            print(f'{i:>2}. OK  {results_file}')

        response = conn.getresponse()
        response_body = response.read()
        results_file.parent.mkdir(parents=True, exist_ok=True)
        results_file.write_bytes(response_body)


if __name__ == '__main__':
    sys.exit(main())
