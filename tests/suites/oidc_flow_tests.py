"""Complete OIDC flow tests."""

import time
from framework import TestSuite
from helpers import OAuthTestClient, http_request
from config import FAAS_BASE_URL, FAAS_HOST, MOCK_OIDC_PORT


def create_oidc_flow_suite():
    """Create OIDC flow test suite."""
    suite = TestSuite("Complete OIDC Flow Tests")

    def test_oidc_discovery(ctx):
        """Test OIDC discovery endpoint"""
        response = http_request('GET', f'http://localhost:{MOCK_OIDC_PORT}/.well-known/openid-configuration')
        assert response.status_code == 200

        discovery = response.json()
        assert discovery['issuer'] == f'http://localhost:{MOCK_OIDC_PORT}'
        assert 'authorization_endpoint' in discovery
        assert 'token_endpoint' in discovery
        assert 'userinfo_endpoint' in discovery

        print("✓ OIDC discovery endpoint works")

    def test_complete_oauth_login_flow(ctx):
        """Test complete OAuth2/OIDC login flow"""
        print("\n[Starting complete OAuth login flow test]")

        # Create OAuth client
        client = OAuthTestClient(client_port=9998)

        try:
            # Perform login flow
            print("[Test] Initiating OAuth login flow...")
            token_response = client.login_flow(FAAS_BASE_URL, timeout=15)

            assert token_response is not None, "Login flow failed"
            assert 'access_token' in token_response, "No access token in response"
            assert 'token_type' in token_response, "No token type in response"
            assert token_response['token_type'] == 'Bearer', "Token type should be Bearer"

            access_token = token_response['access_token']
            print(f"[Test] ✓ Obtained access token: {access_token[:30]}...")

            # Verify token works
            print("[Test] Verifying token by making authenticated request...")
            is_valid = client.test_token(access_token, FAAS_BASE_URL)
            assert is_valid, "Token validation failed"

            print("✓ Complete OAuth login flow successful")

        except Exception as e:
            print(f"[Test] Error: {e}")
            import traceback
            traceback.print_exc()
            raise

    def test_token_expiration(ctx):
        """Test that tokens have proper expiration"""
        client = OAuthTestClient(client_port=9998)

        token_response = client.login_flow(FAAS_BASE_URL, timeout=15)
        assert token_response is not None

        # Check expiration time
        expires_in = token_response.get('expires_in')
        assert expires_in is not None, "No expires_in in token response"
        assert expires_in > 0, "Token expiration should be positive"
        assert expires_in == 31536000, "Token should expire in 1 year (31536000 seconds)"

        print("✓ Token expiration is correctly set")

    def test_invalid_auth_code(ctx):
        """Test that invalid authorization codes are rejected"""
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/oauth2/token',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data='code=invalid-code-12345'
        )

        assert response.status_code == 400
        error_data = response.json()
        assert error_data.get('error') == 'invalid_grant'

        print("✓ Invalid authorization codes are rejected")

    def test_multiple_users(ctx):
        """Test that multiple users can log in and get separate accounts"""
        # First user login
        client1 = OAuthTestClient(client_port=9998)
        token1_response = client1.login_flow(FAAS_BASE_URL, timeout=15)
        assert token1_response is not None

        token1 = token1_response['access_token']

        # Decode token to get account_id
        from jose import jwt
        payload1 = jwt.get_unverified_claims(token1)
        account_id1 = payload1.get('account_id')
        assert account_id1 is not None

        print(f"✓ First user logged in with account_id: {account_id1}")

        # Second login by same user should get same account
        client2 = OAuthTestClient(client_port=9997)
        token2_response = client2.login_flow(FAAS_BASE_URL, timeout=15)
        assert token2_response is not None

        token2 = token2_response['access_token']
        payload2 = jwt.get_unverified_claims(token2)
        account_id2 = payload2.get('account_id')

        # Since both use the same OIDC user (testuser@example.com), they should get the same account
        assert account_id2 == account_id1, "Same user should get same account_id"

        print("✓ Multiple logins by same user get same account")

    def test_oidc_userinfo_endpoint(ctx):
        """Test that OIDC userinfo endpoint works"""
        # First get a token from OIDC provider by going through the flow
        client = OAuthTestClient(client_port=9998)

        # We need to manually get an OIDC access token, not a FaaS token
        # Let's test the OIDC provider directly

        # Start callback server
        client.start_callback_server()

        try:
            # Request authorization from OIDC provider
            auth_url = f'http://localhost:{MOCK_OIDC_PORT}/authorize?client_id=test-client&redirect_uri=http://localhost:9998/callback&response_type=code&scope=openid%20profile%20email&state=test-state'

            response = http_request('GET', auth_url, allow_redirects=False)
            assert response.status_code == 302

            callback_url = response.headers.get('Location')
            assert callback_url is not None

            # Extract code from callback
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(callback_url)
            params = parse_qs(parsed.query)
            code = params.get('code', [None])[0]
            assert code is not None

            # Exchange code for token
            token_response = http_request(
                'POST',
                f'http://localhost:{MOCK_OIDC_PORT}/token',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                data=f'grant_type=authorization_code&code={code}&client_id=test-client&client_secret=test-secret&redirect_uri=http://localhost:9998/callback'
            )

            assert token_response.status_code == 200
            token_data = token_response.json()
            access_token = token_data['access_token']

            # Test userinfo endpoint
            userinfo_response = http_request(
                'GET',
                f'http://localhost:{MOCK_OIDC_PORT}/userinfo',
                headers={'Authorization': f'Bearer {access_token}'}
            )

            assert userinfo_response.status_code == 200
            userinfo = userinfo_response.json()
            assert userinfo['email'] == 'testuser@example.com'
            assert userinfo['preferred_username'] == 'testuser'

            print("✓ OIDC userinfo endpoint works correctly")

        finally:
            client.stop_callback_server()

    suite.add_test(test_oidc_discovery)
    suite.add_test(test_complete_oauth_login_flow)
    suite.add_test(test_token_expiration)
    suite.add_test(test_invalid_auth_code)
    suite.add_test(test_multiple_users)
    suite.add_test(test_oidc_userinfo_endpoint)

    return suite
