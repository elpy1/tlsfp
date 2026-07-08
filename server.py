#!/usr/bin/env python
import argparse
import functools
import json
import logging
import ssl
from socket import IPPROTO_TCP, TCP_NODELAY, MSG_PEEK
import trio
from http_helpers import http_resp, is_http_request, parse_request
from tlsfp import b_to_int, client_hello_data, hexify, make_ja3, make_ja4, parse_tls_record

PEEK_TIMEOUT = 5    # seconds to wait for the full ClientHello record

logging.basicConfig(
    format='%(asctime)s %(levelname)s - %(message)s',
    level=logging.INFO
)

INFO = logging.info
WARNING = logging.warning
ERROR = logging.error
DEBUG = logging.debug

def parse_args():
    """Parse cli arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", type=str, default="/tmp/server.key")
    parser.add_argument("--cert", type=str, default="/tmp/server.crt")
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4433)
    return parser.parse_args()


async def peek_exactly(stream, size):
    """Peek until size bytes are buffered, without consuming them"""
    peek = await stream.socket.recv(size, MSG_PEEK)
    while peek and len(peek) < size:
        await trio.sleep(0.01)   # wait for the rest to arrive
        peek = await stream.socket.recv(size, MSG_PEEK)
    return peek


async def peek_tls_record(stream):
    """
    Peek at the first complete TLS record without consuming it from the
    socket buffer. Returns None if the data is not a TLS handshake.
    A ClientHello can exceed a single TCP segment (e.g. Chrome with a
    post-quantum key share is ~1700 bytes), so keep peeking until the
    full record length from the header is buffered.
    """
    peek = await peek_exactly(stream, 5)
    if len(peek) < 5 or peek[:3] != b'\x16\x03\x01':
        return None
    return await peek_exactly(stream, 5 + b_to_int(peek[3:5]))


async def handle(stream):
    """Handles each new connection"""
    stream.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    addr = stream.socket.getpeername()
    INFO(f'Connection from: {addr[0]}')
    try:
        with trio.fail_after(PEEK_TIMEOUT):
            peek = await peek_tls_record(stream)
        if not peek:
            DEBUG('Not a TLS handshake request. Closing connection.')
            return
        DEBUG(peek)
        stream = trio.SSLStream(stream, tls, server_side=True,
                                https_compatible=True)
        await stream.do_handshake()
        buf = await stream.receive_some(4096)
        if buf and is_http_request(buf):
            INFO(buf)
            req, path, headers = parse_request(buf)
            if req == 'GET':
                if path == '/':
                    resp = http_resp(body='OK', ctype='text/plain')
                elif path == '/tls':
                    rec = parse_tls_record(peek)
                    tls_data = client_hello_data(rec.data.data)
                    fp = {'tls_data': hexify(tls_data._asdict()),
                          'tls_fingerprints': {**make_ja3(tls_data),
                                               **make_ja4(tls_data)}
                          }
                    resp = http_resp(body=json.dumps(fp), ctype='application/json')
                else:
                    resp = http_resp(body=r'¯\_(ツ)_/¯', status_code=404)
            else:
                resp = http_resp(status_code=405)
            await stream.send_all(resp.encode())
    except trio.TooSlowError:
        WARNING(f'Timed out waiting for TLS record from {addr[0]}')
    except Exception as e:
        WARNING(f'Error handling connection from {addr[0]}: {e!r}')
    finally:
        await stream.aclose()


if __name__ == "__main__":
    try:
        args = parse_args()
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(args.cert, args.key)
        trio.run(functools.partial(trio.serve_tcp, handle, args.port, host=args.host))
    # trio delivers Ctrl-C wrapped in a BaseExceptionGroup from the
    # server nursery, so a plain `except KeyboardInterrupt` won't match
    except* KeyboardInterrupt:
        ERROR('Keyboard interrupt. Exiting.')
        raise SystemExit(1) from None
