# You may have to do: pip install cryptography

# This script fetches the remote server's public key embedded in its TLS certificate
# and computes its sha256 hash. This algorithm is the same used to compute
# public key pins, but the intent here is to identify servers which use the same
# keypair for security auditing purposes

# input one or more hosts as --host arguments
# and/or a file containing a list of hosts, one on each line
# each host can have an optional port specifier separated by a colon,
# e.g. abc.com:443

import sys

import socket
import ssl
import base64
import argparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def fetch_ips(hostname, port):
    try:
        info = socket.getaddrinfo(hostname, port)
    except:
        info = []
    if len(info) == 0:
        return [None]
    else:
        return [i[4][0] for i in info]

def fetch_key(hostname, ip, port, cli_cert, cli_key):
    try:
        with socket.create_connection((ip, port)) as sock:
            context = ssl.create_default_context()
            if cli_cert is not None:
                context.load_cert_chain(cli_cert, cli_key)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der)
                return cert.public_key()
    except:
        return None

def compute_pin(pubkey):
    pubkey_bytes = pubkey.public_bytes(
        encoding = serialization.Encoding.DER,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sha2 = hashes.Hash(hashes.SHA256())
    sha2.update(pubkey_bytes)
    hash_bytes = sha2.finalize()
    return base64.b64encode(hash_bytes).decode("ASCII")

def hosts_from_file(fname):
    with open(fname, "r") as f:
        for line in f:
            host = line.strip()
            if host != "":
                yield host

def format_host(host, port):
    return (f"{host}:{port}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch hash of server public key")
    parser.add_argument("--host", help="server hostname", action="append")
    parser.add_argument("--file", help="file with hostnames")
    parser.add_argument("--client-cert", help="optional client cert")
    parser.add_argument("--client-key", help="optional client key")
    args = parser.parse_args()
    hosts = []
    if args.host != None:
        hosts = hosts + []
    if args.file != None:
        hosts = hosts + list(hosts_from_file(args.file))
    for h in hosts:
        fields = h.split(":")
        hostname = fields[0]
        if len(fields) == 2:
            port = int(fields[1])
        else:
            port = 443
        for ip in fetch_ips(hostname, port):
            if ip is None:
                ip = ""
                pin = ""
            else:
                pubkey = fetch_key(hostname, ip, port, args.client_cert, args.client_key)
                if pubkey is None:
                    pin = ""
                else:
                    pin = compute_pin(pubkey)
            print(f"{format_host(h, port):36} {ip:36} {pin}")
