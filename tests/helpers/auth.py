"""Authentication helper utilities."""

import time
import uuid


def generate_test_token(account_id=None, username="testuser", email="test@example.com", jwt_secret="test-secret-key-for-integration-tests"):
    """
    Generate a test JWT token.

    Args:
        account_id: Account ID (generates random UUID if not provided)
        username: Username
        email: Email address
        jwt_secret: Secret key for signing

    Returns:
        Tuple of (token, account_id, payload)
    """
    from jose import jwt as jose_jwt

    if not account_id:
        account_id = str(uuid.uuid4())

    payload = {
        'account_id': account_id,
        'username': username,
        'email': email,
        'iat': int(time.time()),
        'exp': int(time.time()) + 31536000  # 1 year
    }

    token = jose_jwt.encode(payload, jwt_secret, algorithm='HS256')

    return token, account_id, payload
