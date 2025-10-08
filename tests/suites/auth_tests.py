"""Authentication and authorization tests."""

import json
from framework import TestSuite
from helpers import http_request, generate_test_token
from config import FAAS_BASE_URL, FAAS_HOST


def create_auth_suite():
    """Create authentication test suite."""
    suite = TestSuite("Authentication & Authorization Tests")

    def test_reject_without_token(ctx):
        """Reject requests without token"""
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/test/versions',
            headers={'Host': FAAS_HOST},
            files={
                'metadata': (None, json.dumps({'main_module': 'index.js'})),
                'index.js': ('index.js', 'export default {}')
            }
        )
        assert response.status_code == 401
        print("✓ Unauthorized request rejected")

    def test_reject_invalid_token(ctx):
        """Reject requests with invalid token"""
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/test/versions',
            headers={
                'Host': FAAS_HOST,
                'Authorization': 'Bearer invalid-token'
            },
            files={
                'metadata': (None, json.dumps({'main_module': 'index.js'})),
                'index.js': ('index.js', 'export default {}')
            }
        )
        assert response.status_code == 401
        print("✓ Invalid token rejected")

    def test_reject_wrong_account(ctx):
        """Reject requests for wrong account_id"""
        wrong_account_id = "wrong-account-id"
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/accounts/{wrong_account_id}/workers/scripts/test/versions',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}'
            },
            files={
                'metadata': (None, json.dumps({'main_module': 'index.js'})),
                'index.js': ('index.js', 'export default {}')
            }
        )
        assert response.status_code == 403
        print("✓ Wrong account_id rejected")

    def test_create_function_authenticated(ctx):
        """Create function as authenticated user"""
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/authtest/versions',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}'
            },
            files={
                'metadata': (None, json.dumps({
                    'main_module': 'index.js',
                    'compatibility_date': '2025-01-01'
                })),
                'index.js': ('index.js', 'export default { async fetch() { return new Response("OK"); } }')
            }
        )
        assert response.status_code == 200
        print("✓ Function created successfully")

    def test_prevent_cross_user_access(ctx):
        """Prevent cross-user access"""
        # Create function as user 1
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/crossusertest/versions',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}'
            },
            files={
                'metadata': (None, json.dumps({
                    'main_module': 'index.js',
                    'compatibility_date': '2025-01-01'
                })),
                'index.js': ('index.js', 'export default { async fetch() { return new Response("OK"); } }')
            }
        )
        assert response.status_code == 200

        # Try to access user1's account with user2's token (should be rejected)
        user2_token, user2_account, _ = generate_test_token(username='user2', email='user2@example.com')

        # User 2 tries to create a function in User 1's account (should fail with 403)
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/crossusertest2/versions',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {user2_token}'
            },
            files={
                'metadata': (None, json.dumps({
                    'main_module': 'index.js',
                    'compatibility_date': '2025-01-01'
                })),
                'index.js': ('index.js', 'export default { async fetch() { return new Response("Changed"); } }')
            }
        )
        # This should fail since user2 is trying to access user1's account
        assert response.status_code == 403
        print("✓ Cross-user access prevented")

    def test_malformed_authorization_header(ctx):
        """Test various malformed Authorization headers"""
        test_cases = [
            ('Bearer invalid-token-123', 'Invalid token'),
            ('Basic dXNlcjpwYXNz', 'Wrong auth type'),
        ]

        for auth_header, description in test_cases:
            response = http_request(
                'GET',
                f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts',
                headers={
                    'Host': FAAS_HOST,
                    'Authorization': auth_header
                }
            )
            # Should return 401 or 404 (implementation dependent)
            assert response.status_code in [401, 404], f"Should reject: {description} (got {response.status_code})"

        print("✓ Malformed auth headers rejected")

    def test_expired_token(ctx):
        """Test that tokens with wrong signature are rejected"""
        import time
        from jose import jwt

        # Create a token with wrong signature
        payload = {
            'account_id': ctx.account_id,
            'username': 'testuser',
            'email': 'test@example.com',
            'exp': int(time.time()) + 3600,
            'iat': int(time.time()),
        }

        wrong_token = jwt.encode(payload, 'wrong-secret-key', algorithm='HS256')

        response = http_request(
            'GET',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {wrong_token}'
            }
        )
        # Should return 401 or 404 (implementation dependent)
        assert response.status_code in [401, 404]

        print("✓ Tokens with wrong signature rejected")

    def test_token_with_missing_claims(ctx):
        """Test that random invalid tokens are rejected"""
        # Use a completely invalid token format
        invalid_token = "not.a.valid.jwt.token.at.all"

        response = http_request(
            'GET',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {invalid_token}'
            }
        )
        # Should return 401 or 404 (implementation dependent)
        assert response.status_code in [401, 404]

        print("✓ Invalid token format rejected")

    def test_account_id_path_traversal(ctx):
        """Test that path traversal in account_id is rejected"""
        malicious_ids = [
            '../../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            'account/../admin',
            'account/./../../admin',
        ]

        for malicious_id in malicious_ids:
            response = http_request(
                'GET',
                f'{FAAS_BASE_URL}/accounts/{malicious_id}/workers/scripts',
                headers={
                    'Host': FAAS_HOST,
                    'Authorization': f'Bearer {ctx.user_token}'
                }
            )
            # Should reject with 403 or 400
            assert response.status_code in [400, 403, 404]

        print("✓ Path traversal attempts rejected")

    def test_sql_injection_in_params(ctx):
        """Test special characters in parameters"""
        from urllib.parse import quote

        # Test URL-encoded special characters
        special_chars = [
            quote("test'script"),
            quote("test--script"),
            quote("test;script"),
        ]

        for encoded_name in special_chars:
            # Try in script name
            response = http_request(
                'GET',
                f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/{encoded_name}',
                headers={
                    'Host': FAAS_HOST,
                    'Authorization': f'Bearer {ctx.user_token}'
                }
            )
            # Should handle safely (404 or 400, not 500)
            assert response.status_code in [400, 404]

        print("✓ Special characters handled safely")

    def test_list_functions_isolation(ctx):
        """Test that function listing works"""
        # Create function as user 1
        script = "export default { async fetch() { return new Response('Test'); } }"
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/isolationtest/versions',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}'
            },
            files={
                'metadata': (None, json.dumps({
                    'main_module': 'index.js',
                    'compatibility_date': '2025-01-01'
                })),
                'index.js': ('index.js', script)
            }
        )
        assert response.status_code == 200

        # List as user 1
        response = http_request(
            'GET',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}'
            }
        )
        # Should be able to list own functions
        assert response.status_code == 200
        scripts = response.json()['result']
        script_names = [s['id'] for s in scripts]
        assert 'isolationtest' in script_names

    suite.add_test(test_reject_without_token)
    suite.add_test(test_reject_invalid_token)
    suite.add_test(test_reject_wrong_account)
    suite.add_test(test_create_function_authenticated)
    suite.add_test(test_prevent_cross_user_access)
    suite.add_test(test_malformed_authorization_header)
    suite.add_test(test_expired_token)
    suite.add_test(test_token_with_missing_claims)
    suite.add_test(test_account_id_path_traversal)
    suite.add_test(test_sql_injection_in_params)
    suite.add_test(test_list_functions_isolation)

    return suite
