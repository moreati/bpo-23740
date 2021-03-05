#!/usr/bin/env python3
"""
HTTP Server that returns headers and content of the request as the response.
"""
__version__ = "0.1"

import argparse
import contextlib
import email
import http
import http.client
import http.server
import io
import json
import pathlib
import socket
import ssl
import sys

from http import HTTPStatus


def parse_headers(fp, _class=http.client.HTTPMessage):
    """Same as http.client.parse_headers, but returns the raw headers as well.
    """
    headers = []
    while True:
        line = fp.readline(http.client._MAXLINE + 1)
        if len(line) > http.client._MAXLINE:
            raise http.client.LineTooLong("header line")
        headers.append(line)
        if len(headers) > http.client._MAXHEADERS:
            raise http.client.HTTPException("got more than %d headers" % http.client._MAXHEADERS)
        if line in (b'\r\n', b'\n', b''):
            break
    hstring = b''.join(headers).decode('iso-8859-1')
    headers =  email.parser.Parser(_class=_class).parsestr(hstring)
    return hstring, headers


class HTTPDumper(http.server.BaseHTTPRequestHandler):
    server_version = f"HTTPDumper/{__version__}"

    def parse_request(self):
        """Same as http.core.BaseHTTPRequestHandler, but also saves
        self.raw_headers.
        """
        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version
        self.close_connection = True
        requestline = str(self.raw_requestline, 'iso-8859-1')
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 0:
            return False

        if len(words) >= 3:  # Enough to determine protocol version
            version = words[-1]
            try:
                if not version.startswith('HTTP/'):
                    raise ValueError
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ValueError
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad request version (%r)" % version)
                return False
            if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                self.close_connection = False
            if version_number >= (2, 0):
                self.send_error(
                    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED,
                    "Invalid HTTP version (%s)" % base_version_number)
                return False
            self.request_version = version

        if not 2 <= len(words) <= 3:
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "Bad request syntax (%r)" % requestline)
            return False
        command, path = words[:2]
        if len(words) == 2:
            self.close_connection = True
            if command != 'GET':
                self.send_error(
                    HTTPStatus.BAD_REQUEST,
                    "Bad HTTP/0.9 request type (%r)" % command)
                return False
        self.command, self.path = command, path

        # Examine the headers and look for a Connection directive.
        try:
            raw_headers, headers = parse_headers(self.rfile,
                                                 _class=self.MessageClass)
        except http.client.LineTooLong as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Line too long",
                str(err))
            return False
        except http.client.HTTPException as err:
            self.send_error(
                HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Too many headers",
                str(err)
            )
            return False
        self.headers = headers
        self.raw_headers = raw_headers

        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = True
        elif (conntype.lower() == 'keep-alive' and
              self.protocol_version >= "HTTP/1.1"):
            self.close_connection = False
        # Examine the headers and look for an Expect directive
        expect = self.headers.get('Expect', "")
        if (expect.lower() == "100-continue" and
                self.protocol_version >= "HTTP/1.1" and
                self.request_version >= "HTTP/1.1"):
            if not self.handle_expect_100():
                return False
        return True

    def _close_conn(self):
        self.close_connection = True

    def read(self, amt=None):
        self.raw_content = io.BytesIO()

        if self.chunked:
            return self._read_chunked(amt)

        if amt is not None:
            if self.length is not None and amt > self.length:
                # clip the read to the "end of response"
                amt = self.length
            s = self.rfile.read(amt)
            self.raw_content.write(s)
            if not s and amt:
                # Ideally, we would raise IncompleteRead if the content-length
                # wasn't satisfied, but it might break compatibility.
                self._close_conn()
            elif self.length is not None:
                self.length -= len(s)
                if not self.length:
                    self._close_conn()
            return s
        else:
            # Amount is not given (unbounded read) so we must check self.length
            if self.length is None:
                s = self.rfile.read()
                self.raw_content.write(s)
            else:
                try:
                    s = self._safe_read(self.length)
                except http.client.IncompleteRead:
                    self._close_conn()
                    raise
                self.length = 0
            self._close_conn()        # we read everything
            return s

    def _read_next_chunk_size(self):
        # Read the next chunk size from the file
        line = self.rfile.readline(http.client._MAXLINE + 1)
        self.raw_content.write(line)
        if len(line) > http.client._MAXLINE:
            raise http.client.LineTooLong("chunk size")
        i = line.find(b";")
        if i >= 0:
            line = line[:i] # strip chunk-extensions
        try:
            return int(line, 16)
        except ValueError:
            # close the connection as protocol synchronisation is
            # probably lost
            self._close_conn()
            raise

    def _read_and_discard_trailer(self):
        # read and discard trailer up to the CRLF terminator
        ### note: we shouldn't have any trailers!
        while True:
            line = self.rfile.readline(http.client._MAXLINE + 1)
            self.raw_content.write(line)
            if len(line) > http.client._MAXLINE:
                raise http.client.LineTooLong("trailer line")
            if not line:
                # a vanishingly small number of sites EOF without
                # sending the trailer
                break
            if line in (b'\r\n', b'\n', b''):
                break

    def _get_chunk_left(self):
        # return self.chunk_left, reading a new chunk if necessary.
        # chunk_left == 0: at the end of the current chunk, need to close it
        # chunk_left == None: No current chunk, should read next.
        # This function returns non-zero or None if the last chunk has
        # been read.
        chunk_left = self.chunk_left
        if not chunk_left: # Can be 0 or None
            if chunk_left is not None:
                # We are at the end of chunk, discard chunk end
                self._safe_read(2)  # toss the CRLF at the end of the chunk
            try:
                chunk_left = self._read_next_chunk_size()
            except ValueError:
                raise http.client.IncompleteRead(b'')
            if chunk_left == 0:
                # last chunk: 1*("0") [ chunk-extension ] CRLF
                self._read_and_discard_trailer()
                # we read everything; close the "file"
                self._close_conn()
                chunk_left = None
            self.chunk_left = chunk_left
        return chunk_left

    def _read_chunked(self, amt=None):
        assert self.chunked != http.client._UNKNOWN
        value = []
        try:
            while True:
                chunk_left = self._get_chunk_left()
                if chunk_left is None:
                    break

                if amt is not None and amt <= chunk_left:
                    value.append(self._safe_read(amt))
                    self.chunk_left = chunk_left - amt
                    break

                value.append(self._safe_read(chunk_left))
                if amt is not None:
                    amt -= chunk_left
                self.chunk_left = 0
            return b''.join(value)
        except http.client.IncompleteRead:
            raise http.client.IncompleteRead(b''.join(value))

    def _safe_read(self, amt):
        """Read the number of bytes requested.

        This function should be used when <amt> bytes "should" be present for
        reading. If the bytes are truly not available (due to EOF), then the
        IncompleteRead exception can be used to detect the problem.
        """
        data = self.rfile.read(amt)
        self.raw_content.write(data)
        if len(data) < amt:
            raise http.client.IncompleteRead(data, amt-len(data))
        return data

    def do_GET(self):
        try:
            req_transfer_encoding = self.headers["Transfer-Encoding"].lower()
        except (KeyError, AttributeError):
            req_transfer_encoding = None

        try:
            req_content_length = int(self.headers['Content-Length'])
        except (KeyError, ValueError, TypeError):
            req_content_length = None

        if req_transfer_encoding and req_transfer_encoding == "chunked":
            self.chunked = True
            self.chunk_left = None
            self.length = None
            req_content_bytes = self.read()
        elif req_content_length is not None:
            self.chunked = False
            self.length = req_content_length
            req_content_bytes = self.read()
        else:
            req_content_bytes = b""
            self.raw_content = io.BytesIO(req_content_bytes)

        d = {
            "command": self.command,
            "path": self.path,
            "version": self.request_version,
            "headers": [[k, v] for k, v in self.headers.items()],
            "content": req_content_bytes.decode('iso-8859-1'),
            "raw": {
                "requestline": self.raw_requestline.decode('iso-8859-1'),
                "headers": self.raw_headers,
                "content": self.raw_content.getvalue().decode('iso-8859-1'),
            },
        }
        body_str = json.dumps(d, ensure_ascii=True, indent=2)
        body_bytes = body_str.encode('ascii') + b'\r\n'

        self.send_response(http.HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=ascii")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_PATCH = do_GET


# From http.server._get_best_family (Python 3.8+)
def _get_best_family(*address):
    infos = socket.getaddrinfo(
        *address,
        type=socket.SOCK_STREAM,
        flags=socket.AI_PASSIVE,
    )
    family, type, proto, canonname, sockaddr = next(iter(infos))
    return family, sockaddr


# Adapted from http.client.test
def test(HandlerClass=http.server.BaseHTTPRequestHandler,
         ServerClass=http.server.HTTPServer,
         protocol="HTTP/1.0", port=8000, bind=None, ssl_context=None):
    """Run an HTTP or HTTPS server on the specified port.
    """
    ServerClass.address_family, addr = _get_best_family(bind, port)
    HandlerClass.protocol_version = protocol
    with ServerClass(addr, HandlerClass) as httpd:
        host, port = httpd.socket.getsockname()[:2]
        url_host = f'[{host}]' if ':' in host else host
        if ssl_context is not None:
            httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
            proto = "HTTPS"
            url = f"https://{url_host}:{port}/"
        else:
            proto = "HTTP"
            url = f"http://{url_host}:{port}/"
        print(f"Serving {proto} on {host} port {port} ({url}) ...")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received, exiting.")
            sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', metavar='ADDR',
                        help="Bind address (default: all interfaces)")
    parser.add_argument('--port', type=int, default=8000,
                        help="Listening port (default: %(default)i)")
    parser.add_argument('--proto',
                        choices=['http', 'https'],
                        default='http',
                        help="Protocol to serve (default: %(default)s)")
    parser.add_argument('--cert', metavar='PATH',
                        type=pathlib.Path,
                        default='localhost.pem',
                        help="TLS certificate (default: %(default)s)")
    parser.add_argument('--key', metavar='PATH',
                        type=pathlib.Path,
                        default='localhost-key.pem',
                        help="TLS private key (default: %(default)s)")
    args = parser.parse_args()

    if args.proto == 'https':
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(args.cert, args.key)
    else:
        ssl_context = None

    # From http.server
    class DualStackServer(http.server.HTTPServer):
        def server_bind(self):
            # suppress exception when protocol is IPv4
            with contextlib.suppress(Exception):
                self.socket.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            return super().server_bind()

    test(
        HandlerClass=HTTPDumper,
        ServerClass=DualStackServer,
        port=args.port,
        bind=args.bind,
        ssl_context=ssl_context,
    )


if __name__ == '__main__':
    main()
