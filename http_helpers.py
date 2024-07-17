from datetime import datetime, timezone

SERVER_VERSION = 'testing/1.2.3'

METHODS = ('GET', 'HEAD', 'POST', 'PUT', 'DELETE',
            'CONNECT', 'OPTIONS', 'TRACE', 'PATCH')

STATUS_CODE_MSG = {
    200: 'OK',
    404: 'Not Found',
    405: 'Method Not Allowed',
    500: 'Internal Server Error'
}

RESP_TEMPLATE = '''\
HTTP/1.1 {} {}
Date: {}
Server: {}
Content-Length: {}
Content-Type: {}
Connection: close

'''

def is_http_request(buf: bytes):
    req = buf[:8].decode('ascii', errors='ignore')
    return any(m in req for m in METHODS)


def parse_request(buf: bytes):
    items = buf.decode().rstrip().split('\r\n')
    req, path, _ = items[0].split(' ')
    headers = {}
    for i in items[1:]:
        h = i.split(':', 1)
        headers[h[0]] = h[1].lstrip()
    return req, path, headers


def http_resp(body='', ctype='text/html; charset=utf-8', status_code=200):
    resp = RESP_TEMPLATE.format(
        str(status_code),
        STATUS_CODE_MSG[status_code],
        datetime.now(timezone.utc),
        SERVER_VERSION,
        str(len(body.encode())),
        ctype
    )
    if body:
        resp += body
    return resp

