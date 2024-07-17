from tlsfp import parse_tls_handshake, client_hello_data, make_ja4, unpack_variable
import argparse
import sys

PATTERN = b'\x16\x03\x01'

def parse_args():
    """Parse CLI arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=str, required=True)
    return parser.parse_args()


def get_all_records(pcap):
    """Find and return all TLS client handshakes"""
    records = []
    with open(pcap, "rb") as f:
        rest = f.read()
        p_len = len(PATTERN)
        offset = -1
        while (offset := rest.find(PATTERN)) != -1:
            record, rest = unpack_variable(16, rest[offset+p_len:])
            if record[0] == 1:
                records.append(record)
    return records


if __name__ == "__main__":
    args = parse_args()
    records = get_all_records(args.file)

    if not records:
        print('No records found.', file=sys.stderr)
        sys.exit(1)

    for rec in records:
        hs = parse_tls_handshake(rec)
        fp_data = client_hello_data(hs.data)
        print(make_ja4(fp_data).get('ja4'))

