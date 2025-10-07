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
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/test',
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
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/test',
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
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{wrong_account_id}/workers/scripts/test',
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
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/authtest',
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
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/crossusertest',
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

        # Try to access as user 2
        user2_token, user2_account, _ = generate_test_token(username='user2', email='user2@example.com')

        response = http_request(
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{user2_account}/workers/scripts/crossusertest',
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
        assert response.status_code == 403
        print("✓ Cross-user access prevented")

    suite.add_test(test_reject_without_token)
    suite.add_test(test_reject_invalid_token)
    suite.add_test(test_reject_wrong_account)
    suite.add_test(test_create_function_authenticated)
    suite.add_test(test_prevent_cross_user_access)

    return suite
