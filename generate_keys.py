#!/usr/bin/python3
import sys

import multihash
import base58
import jwt

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from libp2p.crypto.keys import protobuf

import binascii

def create_jwt(private_bytes, peerid):
        private_hex = binascii.hexlify(private_bytes).decode()
        # 2022-01-01
        t = 1640991600

        # for hornet
        # the 08011240 is protobuf serialization format
        # 08: field (key-type), 01: value 1, 12: data-with-length, 40: length
        private_key = bytes.fromhex("08011240"+private_hex)

        jwt_data={
            "aud": peerid,
            "jti": str(t),
            "iat": t,
            "iss": peerid,
            "nbf": t,
            "sub": "HORNET",
        }

        jwt_token = jwt.encode(jwt_data, private_key, algorithm="HS256")
        return  jwt_token.decode()

def create_peerid(private_key, public_key):
    ENABLE_INLINING = True
    MAX_INLINE_KEY_LENGTH = 42
    IDENTITY_MULTIHASH_CODE = 0x00

    algo = multihash.Func.sha2_256
    serialized_key = protobuf.PublicKey(key_type=1, data=public_key).SerializeToString()

    if ENABLE_INLINING and len(serialized_key) <= MAX_INLINE_KEY_LENGTH:
        algo = IDENTITY_MULTIHASH_CODE

    mh_digest = multihash.digest(serialized_key, algo)
    peer_id = base58.b58encode(mh_digest.encode()).decode()

    return peer_id

def create_key_pair():
    # Generate new private key
    private_key = Ed25519PrivateKey.generate()

    # Serialize private and public key to bytes
    private_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    )

    return private_bytes, public_bytes

def private_key_to_pem(private_bytes):
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    pem_key = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    return pem_key

def bytes_to_hex(b):
    return binascii.hexlify(b).decode()


def main():
    # generate hornet private and public key
    hornet_private_key, hornet_public_key = create_key_pair()
    hornet_pem = private_key_to_pem(hornet_private_key)

    # generate hornet peer id
    hornet_peerid = create_peerid(hornet_private_key, hornet_public_key)

    # generate hornet jwt token
    hornet_jwt_token = create_jwt(hornet_private_key, hornet_peerid)

    # generate coo private and public key
    coo_private_key, coo_public_key = create_key_pair()
    coo_private_pem = private_key_to_pem(coo_private_key)

    # generate tendermint node/consensus key
    tendermint_private_key, tendermint_public_key = create_key_pair()
    tendermint_private_pem = private_key_to_pem(tendermint_private_key)

    with open(f"identity.key", "w") as f:
        f.write(hornet_pem.decode('utf-8'))

    with open(f"coo.key", "w") as f:
        f.write(coo_private_pem.decode('utf-8'))

    with open(f"tendermint.key", "w") as f:
        f.write(tendermint_private_pem.decode('utf-8'))

    private = f'''# KEEP THIS SAFE

# your hornet private key
hornet_private_key: "{bytes_to_hex(hornet_private_key)}{bytes_to_hex(hornet_public_key)}"

# your hornet jwt token
hornet_jwt_token: "{hornet_jwt_token}"

# your coo private signing key
coo_private_key: "{bytes_to_hex(coo_private_key)}{bytes_to_hex(coo_public_key)}"

# your tendermint private consensus/node key
tendermint_private_key: "{bytes_to_hex(tendermint_private_key)}{bytes_to_hex(tendermint_public_key)}"


'''

    public = f'''# Give this to the IOTA Foundation

# your hornet public key
hornet_public_key: "{bytes_to_hex(hornet_public_key)}"

# your hornet peering ID
hornet_peer_id: "{hornet_peerid}"

# your coo public signing key
coo_public_key: "{bytes_to_hex(coo_public_key)}"

# your tendermint public key
tendermint_public_key: "{bytes_to_hex(tendermint_public_key)}"


'''

    with open(f"private.txt", "w") as f:
        f.write(private)

    with open(f"public.txt", "w") as f:
        f.write(public)

    sys.exit(0)

if __name__ == "__main__":
    main()
