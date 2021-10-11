# You may have to do: pip install cryptography

# This script fetches the remote server's public key embedded in its TLS certificate
# and computes its sha256 hash. This algorithm is the same used to compute
# public key pins, but the intent here is to identify servers which use the same
# keypair for security auditing purposes

import sys

import socket
import ssl
import base64
import argparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def fetch_key(hostname, port, cli_cert, cli_key):
    with socket.create_connection((hostname, port)) as sock:
        context = ssl.create_default_context()
        if cli_cert is not None:
            context.load_cert_chain(cli_cert, cli_key)
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der)
            return cert.public_key()

def compute_pin(pubkey):
    pubkey_bytes = pubkey.public_bytes(
        encoding = serialization.Encoding.DER,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sha2 = hashes.Hash(hashes.SHA256())
    sha2.update(pubkey_bytes)
    hash_bytes = sha2.finalize()
    return base64.b64encode(hash_bytes)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch hash of server public key")
    parser.add_argument("host", help="server hostname")
    parser.add_argument("--port", type=int, help="optional port, defaults to 443")
    parser.set_defaults(port=443)
    parser.add_argument("--client-cert", help="optional client cert")
    parser.add_argument("--client-key", help="optional client key")
    args = parser.parse_args()
    pubkey = fetch_key(args.host, args.port, args.client_cert, args.client_key)
    pin = compute_pin(pubkey)
    print(pin)
