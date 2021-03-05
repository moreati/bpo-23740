#!/usr/bin/env python3

import os
import socket
import time
import subprocess
import sys

# Adapted from https://github.com/mitogen-hq/mitogen/blob/60fbea4b59cb558ffc3c8cfe9d1531367fc4be71/tests/testlib.py#L118-L202
def wait_for_port(host, port, connect_timeout=0.5, overall_timeout=5.0, sleep=0.1):
    """Attempt to connect to host/port, for upto overall_timeout seconds.
    """
    start = time.monotonic()
    addr = (host, port)

    while time.monotonic() - start < overall_timeout:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(connect_timeout)
        try:
            sock.connect(addr)
        except socket.error:
            # Failed to connect. So wait then retry.
            time.sleep(sleep)
            continue

        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        return
    else:
        raise socket.timeout(f'Timed out while connecting to {host}:{port}')


def main():
    http_port = 8000
    http_argv = ['./http_dumper.py', f'--port={http_port}', '--proto=http']
    https_port = 8443
    https_argv = ['./http_dumper.py', f'--port={https_port}', '--proto=https']
    with subprocess.Popen(http_argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as http_proc, \
         subprocess.Popen(https_argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as https_proc:
        # FIXME fails on Python 3.6 & 3.7
        # wait_for_port('localhost', http_port)
        # wait_for_port('localhost', https_port)
        time.sleep(2)
        subprocess.check_call(['./http_tests.py'] + sys.argv[1:])
        http_proc.terminate()
        https_proc.terminate()


if __name__ == '__main__':
    sys.exit(main())
