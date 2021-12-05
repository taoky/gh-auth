#!/usr/bin/env python3
try:
    import nacl.encoding
    import nacl.signing
except ImportError:
    print("Please install PyNaCl")
    print("Command: `pip install PyNaCl` or `apt install python3-nacl`")
    exit(1)

k = nacl.signing.SigningKey.generate()
print(f"NACL_PRIVKEY=\"{k.encode(encoder=nacl.encoding.HexEncoder).decode()}\"")
print(f"NACL_PUBKEY=\"{k.verify_key.encode(encoder=nacl.encoding.HexEncoder).decode()}\"")
