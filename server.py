#!/usr/bin/env python
import argparse
import json
import logging
from curio.socket import IPPROTO_TCP, TCP_NODELAY
from curio.network import tcp_server
from curio import run, socket, ssl
from http_helpers import http_resp, is_http_request, parse_request
from tlsfp import client_hello_data, hexify, make_ja3, make_ja4, parse_tls_record

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


async def handle(conn, addr):
    """Handles each new connection"""
    conn.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    INFO(f'Connection from: {addr[0]}')
    peek = await conn.recv(1024, socket.MSG_PEEK)
    if peek and peek[:3] == b'\x16\x03\x01':
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
    else:
        DEBUG('Not a TLS handshake request. Closing connection.')
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
