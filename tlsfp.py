from hashlib import md5, sha256
from typing import NamedTuple
from tls_vars import *

class TLSRecord(NamedTuple):
    """
    TLS Record object
    RFC 5246: https://datatracker.ietf.org/doc/html/rfc5246#appendix-A.1

      struct {
          ContentType type;                             # 22: Handshake
          ProtocolVersion version;
          uint16 length;
          opaque fragment[TLSPlaintext.length];
      } TLSPlaintext;
    """
    content_type: bytes
    version: bytes
    length: bytes
    data: bytes

class TLSHandshake(NamedTuple):
    """
    TLS Handshake object
    RFC 8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4

      struct {
          HandshakeType msg_type;    /* handshake type */
          uint24 length;             /* remaining bytes in message */
          select (Handshake.msg_type) {
              case client_hello:          ClientHello;
              ...
          };
      } Handshake;
    """
    msg_type: bytes
    length: bytes
    data: bytes

class TLSClientHello(NamedTuple):
    """
    TLS ClientHello object
    RFC 8446: https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2

    Structure of this message:
      uint16 ProtocolVersion;
      opaque Random[32];
      uint8 CipherSuite[2];    /* Cryptographic suite selector */

      struct {
          ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
          Random random;
          opaque legacy_session_id<0..32>;
          CipherSuite cipher_suites<2..2^16-2>;
          opaque legacy_compression_methods<1..2^8-1>;
          Extension extensions<8..2^16-1>;
      } ClientHello;
    """
    protocol_version: bytes
    random: bytes
    session_id_length: bytes
    session_id: bytes
    cipher_suites_length: bytes
    cipher_suites: list[bytes]
    compression_methods_length: bytes
    compression_methods: bytes
    extensions_length: bytes
    extensions: list[bytes]

class TLSClientHelloData(NamedTuple):
    """
    TLS ClientHello Data object
    This contains all the data needed to build a fingerprint
    """
    protocol_version: bytes
    cipher_suites: list
    extensions: list
    server_name: bytes | None = None
    ec_point_formats: list = []
    supported_groups: list = []
    alpn: list = []
    signature_algorithms: list = []
    supported_versions: list = []


def parse_tls_record(buf: bytes, raw: bool = False):
    """ Check and parse TLS Record"""
    if buf[0] != 0x16:
        raise ValueError('Not a Handshake message.')
    data, rest = unpack_variable(16, buf[3:])
    #if rest:
    #    print('Unexpected data in buf. Ignoring.')
    return TLSRecord(
        content_type=buf[0:1],
        version=buf[1:3],
        length=buf[3:5],
        data=data if raw else parse_tls_handshake(data)
    )


def parse_tls_handshake(buf: bytes, raw: bool = False):
    """Check and parse TLS Handshake"""
    if buf[0] != 0x01:
        raise ValueError('Not a ClientHello message.')
    data, rest = unpack_variable(24, buf[1:])
    #if rest:
    #    print('Unexpected data in buf. Ignoring.')
    return TLSHandshake(
        msg_type=buf[0:1],
        length=buf[1:4],
        data=data if raw else parse_client_hello(data)
    )


def parse_client_hello(buf: bytes):
    """Check and parse TLS ClientHello"""
    items = []
    offset = 0
    items.append(buf[offset:2])                     # Protocol Version (2 bytes)
    offset +=2
    items.append(buf[offset:offset+32])             # Random (32 bytes)
    offset +=32
    items.append(buf[offset:offset+1])              # SessionID length (1 byte)
    sid_len = buf[offset:offset+1][0]
    offset +=1
    items.append(buf[offset:offset+sid_len])        # SessionID (variable length)
    offset +=sid_len
    items.append(buf[offset:offset+2])              # Cipher suites length (2 bytes)
    cs, rest = unpack_variable(16, buf[offset:])    # Cipher suites (variable)
    items.append(unpack_fixed(16, cs))
    items.append(rest[0:1])                         # Compression methods Length (1 byte)
    cm, rest = unpack_variable(8, rest)             # Compression methods (variable)
    items.append(cm)
    items.append(rest[:2])                          # Extensions length (2 bytes)
    ex, rest = unpack_variable(16, rest)            # Extensions (variable)
    items.append(parse_extensions(ex))
    return TLSClientHello(*items)


def client_hello_data(hello: TLSClientHello):
    """Check and parse TLS ClientHello data"""
    return TLSClientHelloData(
        protocol_version = hello.protocol_version,
        cipher_suites = hello.cipher_suites,
        extensions = [e[:2] for e in hello.extensions],
        **process_extensions(hello.extensions)
    )


def degrease(data: list[bytes]):
    """
    GREASE values in extensions, named groups, signature algorithms,
    versions, cipher suites and ALPN identifiers must be ignored when
    building the TLS fingerprints.
    https://www.rfc-editor.org/rfc/rfc8701.html
    """
    if not isinstance(data, list):
        raise TypeError('Invalid data. Expected a list.')
    return [s for s in data if b_to_int(s) not in RESERVED]


def make_ja3(data: TLSClientHelloData):
    """https://github.com/salesforce/ja3"""
    def ja3_seq(fp):
        return '-'.join([str(b_to_int(i)) for i in degrease(fp)])

    ja3_r = '{},{},{},{},{}'.format(
        str(b_to_int(data.protocol_version)),
        ja3_seq(data.cipher_suites),
        ja3_seq(data.extensions),
        ja3_seq(data.supported_groups),
        ja3_seq(data.ec_point_formats)
    )
    ja3 = md5(ja3_r.encode()).hexdigest()
    return {
        'ja3_r': ja3_r,
        'ja3': ja3
    }


def make_ja4(data: TLSClientHelloData):
    """https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md"""
    def hashh(ja4_segment):
        return sha256(ja4_segment.encode()).hexdigest()[:12]

    def ja4_seq(fp, rm_exts=False):
        if rm_exts:  # To remove: SNI (0), ALPN (16)
            fp = [i for i in fp if b_to_int(i) not in (0, 16)]
        return ','.join([i.hex() for i in degrease(fp)])

    transport = 't'     # TLS over TCP is all we accept at this stage
    version = b_to_int(data.protocol_version)
    alpn = '00'
    if data.supported_versions:
        supported_versions = degrease(data.supported_versions)
        version = max(b_to_int(v) for v in supported_versions)
    if data.alpn:
        alpns = degrease(data.alpn)
        alpn = '99' if alpns[0][0] > 127 else f'{chr(alpns[0][0])}{chr(alpns[0][-1])}'
    ver = TLS_VERSIONS[version]
    sni = 'd' if data.server_name else 'i'
    ciphers_len = len(degrease(data.cipher_suites))
    extensions_len = len(degrease(data.extensions))
    sig_algs = ja4_seq(data.signature_algorithms)

    seg1 = f'{transport}{ver}{sni}{ciphers_len:02}{extensions_len:02}{alpn}'
    seg2_ro = ja4_seq(data.cipher_suites)
    seg2_r = ja4_seq(sorted(data.cipher_suites))
    seg3_ro = ja4_seq(data.extensions)+'_'+sig_algs
    seg3_r = ja4_seq(sorted(data.extensions), rm_exts=True)+'_'+sig_algs

    return {
        'ja4_r':  f'{seg1}_{seg2_r}_{seg3_r}',
        'ja4':    f'{seg1}_{hashh(seg2_r)}_{hashh(seg3_r)}',
        'ja4_ro': f'{seg1}_{seg2_ro}_{seg3_ro}',
        'ja4_o':  f'{seg1}_{hashh(seg2_ro)}_{hashh(seg3_ro)}'
    }


def parse_extensions(buf: bytes):
    """Unpack extensions"""
    exts = []
    while len(buf):
        ext_type = buf[:2]
        ext_length = buf[2:4]
        ext_data, buf = unpack_variable(16, buf[2:])
        exts.append(ext_type+ext_length+ext_data)
    return exts


def process_extensions(extensions: list[bytes]):
    """
    To get extension types for targets:
    https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.txt

    https://www.rfc-editor.org/rfc/rfc8422.html#section-5.1
    * elliptic_curves extension has since been renamed to 'supported_groups' *
    """
    # The following are used for TLS client fingerprinting:
    targets = {
        0:  'server_name',          # https://www.rfc-editor.org/rfc/rfc4366#section-3.1
        10: 'supported_groups',     # 16 bit length, 16 bit values
        11: 'ec_point_formats',     # 8 bit length, 8 bit values
        13: 'signature_algorithms', # 16 bit length, 16 bit values
        16: 'alpn',                 # 16 bit length, 8 bit protocol length, variable value
        43: 'supported_versions'    # 8 bit length, 16 bit values
    }

    offset = 4                      # Extension Type (2 bytes) + Extension Lenght (2 bytes)
    items = {}
    for e in extensions:
        ext_type = b_to_int(e[:2])
        ext_name = targets.get(ext_type)
        match ext_type:
            case 0:
                # server_name list length (2 bytes), sn type (1 byte), sn length (2 bytes)
                items[ext_name] = e[offset:][5:]
            case 10 | 13:
                ext_data, _ = unpack_variable(16, e[offset:])
                items[ext_name] = unpack_fixed(16, ext_data)
            case 11:
                ext_data, _ = unpack_variable(8, e[offset:])
                items[ext_name] = unpack_fixed(8, ext_data)
            case 16:
                alpns = []
                alpn_data, _ = unpack_variable(16, e[offset:])
                while len(alpn_data):
                    a, alpn_data = unpack_variable(8, alpn_data)
                    alpns.append(a)
                items[ext_name] = alpns
            case 43:
                ext_data, _ = unpack_variable(8, e[offset:])
                items[ext_name] = unpack_fixed(16, ext_data)
    return items


def b_to_int(byte_string: bytes):
    """Convert a given byte string to int"""
    return int.from_bytes(byte_string, byteorder='big')


def unpack_variable(bits: int, buf: bytes):
    """Unpack and return tuple of variable sized data and any remaining data"""
    offset = bits // 8
    length = b_to_int(buf[:offset])
    if len(buf) < (offset + length):
        raise ValueError(f'Invalid buf size. Expected length: {str(length)}')
    data = buf[offset:offset+length]
    rest = buf[offset+length:]
    return data, rest


def unpack_fixed(bits: int, buf: bytes):
    """
    Unpack and return list of fixed size data"""
    byte_length = bits // 8
    if len(buf) % byte_length != 0:
        raise ValueError('Invalid buf size.')
    data = []
    for i in range(0, len(buf), byte_length):
        data.append(buf[i:i+byte_length])
    return data


def intify(data):
    """Convert data in bytes to int"""
    if isinstance(data, dict):
        return {k: intify(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [intify(item) for item in data]
    elif isinstance(data, bytes):
        return b_to_int(data)
    else:
        return data


def hexify(data):
    """Convert data in bytes to hex"""
    if isinstance(data, dict):
        return {k: hexify(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [hexify(item) for item in data]
    elif isinstance(data, bytes):
        return data.hex()
    else:
        return data
