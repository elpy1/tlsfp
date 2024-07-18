from tlsfp import client_hello_data, make_ja4, parse_tls_record
from tls_vars import TLS_VERSIONS
import argparse
import sys

PATTERN = b'\x16\x03'

def parse_args():
    """Parse CLI arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=str, required=True)
    return parser.parse_args()

def get_all_records(pcap):
    """Find and return all TLS client handshakes"""
    records = []
    versions = [int.to_bytes(v, 2) for v in TLS_VERSIONS]
    with open(pcap, "rb") as f:
        rest = f.read()
        offset = -1
        while (offset := rest.find(PATTERN, offset+1)) != -1:
            if rest[offset+1:offset+3] not in versions:
                continue
            try:
                record = parse_tls_record(rest[offset:])
            except ValueError:
                continue
            records.append(record)
    return records


if __name__ == "__main__":
    args = parse_args()
    records = get_all_records(args.file)

    if not records:
        print('No records found.', file=sys.stderr)
        sys.exit(1)

    for rec in records:
        fp_data = client_hello_data(rec.data.data)
        print(make_ja4(fp_data).get('ja4'))

