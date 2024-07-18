import argparse
import dpkt
import sys
from tlsfp import client_hello_data, make_ja3, make_ja4, parse_tls_record


def parse_args():
    """CLI arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=str, required=True)
    return parser.parse_args()


def get_fingerprints(buf: bytes):
    """Parse TLS client handshake data and return fingerprints"""
    try:
        record = parse_tls_record(buf)
    except ValueError:
        return

    handshake = record.data
    fp_data = client_hello_data(handshake.data)
    return {
        **make_ja3(fp_data),
        **make_ja4(fp_data)
    }


def main(fname: str):
    """Loop through pcap packets and print out JA4 TLS fingerprints"""
    with open(fname, 'rb') as f:
        pcap = dpkt.pcap.UniversalReader(f)
        for _, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            try:
                ip = eth.data
                tcp = ip.data
                rest = tcp.data
            except AttributeError:
                continue

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
