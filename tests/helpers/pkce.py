"""PKCE helper utilities for OAuth2 testing."""

import hashlib
import base64
import secrets


def generate_code_verifier(length=128):
    """
    Generate a PKCE code verifier.

    Args:
        length: Length of the verifier (43-128 characters after base64url encoding)

    Returns:
        Base64url-encoded random string
    """
    # Generate random bytes
    verifier_bytes = secrets.token_bytes(96)  # 96 bytes = 128 chars after base64url

    # Base64url encode (no padding)
    verifier = base64.urlsafe_b64encode(verifier_bytes).decode('utf-8').rstrip('=')

    # Truncate to desired length
    return verifier[:length]


def generate_code_challenge(verifier, method='S256'):
    """
    Generate a PKCE code challenge from a verifier.

    Args:
        verifier: The code verifier string
        method: 'S256' for SHA256, 'plain' for plain text

    Returns:
        Base64url-encoded challenge string
    """
    if method == 'S256':
        # SHA256 hash the verifier
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        # Base64url encode (no padding)
        challenge = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
        return challenge
    elif method == 'plain':
        # Plain verifier is the challenge
        return verifier
    else:
        raise ValueError(f"Unknown PKCE method: {method}")


def generate_pkce_pair(method='S256'):
    """
    Generate a PKCE code verifier and challenge pair.

    Args:
        method: 'S256' or 'plain'

    Returns:
        Tuple of (verifier, challenge, method)
    """
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier, method)
    return verifier, challenge, method
