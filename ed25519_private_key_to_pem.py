#!/usr/bin/python3
# helper script to generate a PEM for an ed25519 private key
import sys
import os
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import binascii

def main(hex_key, output_filename):
    # Check hex_key length
    if len(hex_key) != 64:
        print("Error: Invalid hex string length. An Ed25519 private key should be 64 characters long.")
        return

    # Check if output file already exists
    if os.path.exists(output_filename):
        print(f"Error: File {output_filename} already exists. Not overwriting.")
        return

    try:
        # Convert hex to binary
        bin_key = binascii.unhexlify(hex_key)
    except binascii.Error:
        print("Error: Invalid hex string.")
        return

    # Create private key object from binary key
    private_key = Ed25519PrivateKey.from_private_bytes(bin_key)

    # Convert private key object to PEM format
    pem_key = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    # Write PEM key to file
    with open(output_filename, 'wb') as pem_out:
        pem_out.write(pem_key)

    print(f"PEM key written to {output_filename}.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 script.py <hex_key> <output_filename>")
    else:
        main(sys.argv[1], sys.argv[2])

