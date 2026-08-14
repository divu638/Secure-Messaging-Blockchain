"""
backend/blockchain/signatures.py
----------------------------------
Server-side RSA digital signature verification.
The client signs messages with their RSA-PSS private key (Web Crypto API).
The server verifies using the stored public key (PEM/SPKI format).
"""

import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def verify_rsa_signature(public_key_pem: str, message: str, signature_b64: str) -> bool:
    """
    Verify an RSA-PSS signature (SHA-256) produced by the Web Crypto API.

    Args:
        public_key_pem:  SPKI PEM public key stored on server.
        message:         The original plaintext message (before encryption).
        signature_b64:   Base64-encoded signature from client.

    Returns:
        True if valid, False otherwise.
    """
    try:
        # Decode PEM public key
        pub_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"),
            backend=default_backend(),
        )

        # Decode base64 signature
        signature_bytes = base64.b64decode(signature_b64)

        # Verify using RSA-PSS with SHA-256
        pub_key.verify(
            signature_bytes,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=32,
            ),
            hashes.SHA256(),
        )
        return True

    except (InvalidSignature, ValueError, TypeError, Exception):
        return False
