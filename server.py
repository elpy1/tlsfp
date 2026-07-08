#!/usr/bin/env python
import argparse
import json
import logging
from curio.socket import IPPROTO_TCP, TCP_NODELAY
from curio.network import tcp_server
from curio import run, socket, sleep, ssl, timeout_after, TaskTimeout
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


async def peek_exactly(conn, size):
    """Peek until size bytes are buffered, without consuming them"""
    peek = await conn.recv(size, socket.MSG_PEEK)
    while peek and len(peek) < size:
        await sleep(0.01)   # wait for the rest to arrive
        peek = await conn.recv(size, socket.MSG_PEEK)
    return peek


async def peek_tls_record(conn):
    """
    Peek at the first complete TLS record without consuming it from the
    socket buffer. Returns None if the data is not a TLS handshake.
    A ClientHello can exceed a single TCP segment (e.g. Chrome with a
    post-quantum key share is ~1700 bytes), so keep peeking until the
    full record length from the header is buffered.
    """
    peek = await peek_exactly(conn, 5)
    if len(peek) < 5 or peek[:3] != b'\x16\x03\x01':
        return None
    return await peek_exactly(conn, 5 + b_to_int(peek[3:5]))


async def handle(conn, addr):
    """Handles each new connection"""
    conn.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    INFO(f'Connection from: {addr[0]}')
    try:
        peek = await timeout_after(PEEK_TIMEOUT, peek_tls_record(conn))
        if not peek:
            DEBUG('Not a TLS handshake request. Closing connection.')
            return
        DEBUG(peek)
        conn = await tls.wrap_socket(conn, server_side=True)
        buf = await conn.recv(4096)
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
            await conn.send(resp.encode())
    except TaskTimeout:
        WARNING(f'Timed out waiting for TLS record from {addr[0]}')
    except Exception as e:
        WARNING(f'Error handling connection from {addr[0]}: {e!r}')
    finally:
        await conn.close()


if __name__ == "__main__":
    try:
        args = parse_args()
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(args.cert, args.key)
        run(tcp_server(args.host, args.port, handle))
    except KeyboardInterrupt as e:
        ERROR('Keyboard interrupt. Exiting.')
        raise SystemExit(1) from e
