import argparse
import dpkt
import sys
from tlsfp import client_hello_data, make_ja3, make_ja4, parse_tls_record


def parse_args():
    """CLI arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=str, required=True)
    return parser.parse_args()


# Link-layer header type --> dpkt decoder
# https://www.tcpdump.org/linktypes.html
LINK_DECODERS = {
    0:   dpkt.loopback.Loopback,    # LINKTYPE_NULL
    1:   dpkt.ethernet.Ethernet,    # LINKTYPE_ETHERNET
    113: dpkt.sll.SLL,              # LINKTYPE_LINUX_SLL (tcpdump -i any)
    276: dpkt.sll2.SLL2,            # LINKTYPE_LINUX_SLL2
}


def get_fingerprints(buf: bytes):
    """Parse TLS client handshake data and return fingerprints"""
    # Scanning arbitrary payload offsets means garbage regularly reaches
    # the parser; treat any parse failure as 'not a ClientHello'.
    try:
        record = parse_tls_record(buf)
        fp_data = client_hello_data(record.data.data)
        return {
            **make_ja3(fp_data),
            **make_ja4(fp_data)
        }
    except (ValueError, IndexError, KeyError):
        return


def main(fname: str):
    """Loop through pcap packets and print out JA4 TLS fingerprints"""
    with open(fname, 'rb') as f:
        pcap = dpkt.pcap.UniversalReader(f)
        decoder = LINK_DECODERS.get(pcap.datalink())
        if decoder is None:
            sys.exit(f'Unsupported link-layer type: {pcap.datalink()}')
        for _, buf in pcap:
            try:
                frame = decoder(buf)
            except dpkt.dpkt.UnpackError:
                continue
            tcp = getattr(frame.data, 'data', None)
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            rest = tcp.data

            offset = -1
            while (offset := rest.find(b'\x16\x03', offset + 1)) != -1:
                if fp := get_fingerprints(rest[offset:]):
                    print(fp.get('ja4'))


if __name__ == "__main__":
    try:
        args = parse_args()
        main(args.file)
    except KeyboardInterrupt:
        print('Keyboard interrupt. Exiting.', file=sys.stderr)
        sys.exit(1)
