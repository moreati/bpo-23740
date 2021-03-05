#!/usr/bin/env python3
"""
Submit http requests with different types supplied as the content
"""

import argparse
import http.client
import io
import pathlib
import ssl
import sys
import urllib.parse


HERE = pathlib.Path(__file__).parent


class Readable:
    def __init__(self, fp):
        self.fp = fp

    def read(self, size=None):
        return self.fp.read(size)


TEST_CLIENTS = {
    'HTTPConnection': ('http://localhost:8000', http.client.HTTPConnection),
    'HTTPSConnection': ('https://localhost:8443', http.client.HTTPSConnection),
}


TEST_DATAS = {
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


TEST_CASES = [
    (client_name, url, client, case_name, data)
    for client_name, (url, client) in TEST_CLIENTS.items()
    for case_name, data in TEST_DATAS.items()
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cafile', metavar='PATH',
                        type=pathlib.Path,
                        default='rootCA.pem',
                        help="CA certificate(s) file (default: %(default)s)")
    parser.add_argument('--results-base', metavar='PATH',
                        type=pathlib.Path,
                        default='results')
    args = parser.parse_args()

    for i, case in enumerate(TEST_CASES):
        client_name, url, client, name, body = case
        results_file = args.results_base / client_name / name / 'body.json'
        url = urllib.parse.urlparse(url)
        if url.scheme == 'https':
            ssl_context = ssl.create_default_context(
                cafile=args.cafile.expanduser(),
            )
            conn = client(url.netloc, context=ssl_context)
        else:
            conn = client(url.netloc)

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

    version_file = args.results_base / 'version.txt'
    version_file.write_text(sys.version + '\n')


if __name__ == '__main__':
    sys.exit(main())
