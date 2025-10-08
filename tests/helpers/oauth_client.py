"""OAuth client for testing the complete OIDC flow."""

import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread, Event
from urllib.parse import parse_qs, urlparse, urlencode
from .http_client import http_request


class OAuthTestClient:
    """OAuth client that simulates a user logging in through OIDC."""

    def __init__(self, client_port=9998):
        self.client_port = client_port
        self.server = None
        self.thread = None

        # Storage for callback data
        self.callback_event = Event()
        self.callback_code = None
        self.callback_state = None
        self.callback_error = None

    def start_callback_server(self):
        """Start callback server to receive authorization code."""
        handler = self._create_handler()
        self.server = HTTPServer(('localhost', self.client_port), handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop_callback_server(self):
        """Stop callback server."""
        if self.server:
            self.server.shutdown()
            self.server = None
            self.thread = None

    def _create_handler(self):
        """Create callback handler."""
        client = self

        class CallbackHandler(BaseHTTPRequestHandler):
            """Handle OAuth callback."""

            def log_message(self, format, *args):
                """Suppress log messages."""
                pass

            def do_GET(self):
                """Handle GET request for callback."""
                parsed_url = urlparse(self.path)
                params = parse_qs(parsed_url.query)

                # Extract code and state
                client.callback_code = params.get('code', [None])[0]
                client.callback_state = params.get('state', [None])[0]
                client.callback_error = params.get('error', [None])[0]

                # Signal that callback was received
                client.callback_event.set()

                # Send response
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()

                if client.callback_code:
                    html = '<html><body><h1>Login Successful!</h1><p>You can close this window.</p></body></html>'
                else:
                    html = f'<html><body><h1>Login Failed</h1><p>Error: {client.callback_error}</p></body></html>'

                self.wfile.write(html.encode())

        return CallbackHandler

    def login_flow(self, faas_base_url, timeout=10, code_challenge=None, code_challenge_method=None, code_verifier=None):
        """
        Perform complete OAuth login flow.

        Args:
            faas_base_url: Base URL of FaaS service (e.g., http://localhost:8080)
            timeout: Timeout in seconds to wait for callback
            code_challenge: Optional PKCE code challenge
            code_challenge_method: Optional PKCE code challenge method (S256 or plain)
            code_verifier: Optional PKCE code verifier (for token exchange)

        Returns:
            dict with access_token and other token response data, or None if failed
        """
        # Reset state
        self.callback_event.clear()
        self.callback_code = None
        self.callback_state = None
        self.callback_error = None

        # Start callback server
        self.start_callback_server()

        try:
            # Step 1: Initiate OAuth flow by redirecting to FaaS /oauth2/auth
            # This will redirect to OIDC provider's /authorize
            # Which will auto-approve and redirect back to FaaS /auth/callback
            # FaaS will then redirect to our callback URL with the code

            # We need to manually follow the redirect chain
            print(f"[OAuth Client] Starting login flow...")

            # Generate a random state for CSRF protection
            import secrets
            state = secrets.token_urlsafe(32)

            # Build auth URL with required parameters
            auth_url = f'{faas_base_url}/oauth2/auth?state={state}&redirect_uri=http://localhost:{self.client_port}/callback'

            # Add PKCE parameters if provided
            if code_challenge:
                auth_url += f'&code_challenge={code_challenge}'
                if code_challenge_method:
                    auth_url += f'&code_challenge_method={code_challenge_method}'

            print(f"[OAuth Client] Step 1: GET {auth_url}")

            # We can't easily follow redirects automatically, so we'll simulate the flow:
            # 1. User clicks "Login with OIDC"
            # 2. App redirects to /oauth2/auth
            # 3. FaaS redirects to OIDC provider /authorize
            # 4. OIDC provider auto-approves and redirects to FaaS /auth/callback with code
            # 5. FaaS exchanges code for token with OIDC provider
            # 6. FaaS creates user and generates auth code
            # 7. FaaS redirects to our callback with code

            # For testing, we'll directly call the OIDC authorize endpoint
            # to get a code, then call FaaS callback, then exchange for token

            # Actually, let's trace through the real flow by following redirects manually
            response = http_request('GET', auth_url, allow_redirects=False)

            if response.status_code != 302:
                print(f"[OAuth Client] Error: Expected redirect from /oauth2/auth, got {response.status_code}")
                return None

            # Extract redirect location (should be OIDC provider)
            oidc_auth_url = response.headers.get('Location')
            if not oidc_auth_url:
                print(f"[OAuth Client] Error: No Location header in redirect")
                return None

            print(f"[OAuth Client] Step 2: Following redirect to OIDC provider: {oidc_auth_url}")

            # Follow redirect to OIDC provider
            response = http_request('GET', oidc_auth_url, allow_redirects=False)

            if response.status_code != 302:
                print(f"[OAuth Client] Error: Expected redirect from OIDC /authorize, got {response.status_code}")
                return None

            # Extract redirect back to FaaS callback
            faas_callback_url = response.headers.get('Location')
            if not faas_callback_url:
                print(f"[OAuth Client] Error: No Location header from OIDC")
                return None

            print(f"[OAuth Client] Step 3: Following redirect back to FaaS: {faas_callback_url}")

            # Follow redirect to FaaS callback
            response = http_request('GET', faas_callback_url, allow_redirects=False)

            if response.status_code != 302:
                print(f"[OAuth Client] Error: Expected redirect from FaaS /auth/callback, got {response.status_code}")
                print(f"[OAuth Client] Response: {response.text}")
                return None

            # Extract redirect to our callback
            our_callback_url = response.headers.get('Location')
            if not our_callback_url:
                print(f"[OAuth Client] Error: No Location header from FaaS callback")
                return None

            print(f"[OAuth Client] Step 4: Following redirect to client callback: {our_callback_url}")

            # This should trigger our callback server
            parsed = urlparse(our_callback_url)
            callback_path = parsed.path + ('?' + parsed.query if parsed.query else '')

            # Make request to our own callback server
            response = http_request('GET', f'http://localhost:{self.client_port}{callback_path}')

            # Wait for callback to be processed
            if not self.callback_event.wait(timeout=timeout):
                print(f"[OAuth Client] Error: Timeout waiting for callback")
                return None

            if self.callback_error:
                print(f"[OAuth Client] Error in callback: {self.callback_error}")
                return None

            if not self.callback_code:
                print(f"[OAuth Client] Error: No authorization code received")
                return None

            print(f"[OAuth Client] Step 5: Received authorization code: {self.callback_code[:20]}...")

            # Save the code for reuse tests
            self.last_code = self.callback_code

            # Save the code_verifier for later use
            self.last_code_verifier = code_verifier if code_challenge else None

            # Step 2: Exchange authorization code for access token
            token_url = f'{faas_base_url}/oauth2/token'
            token_data = {
                'code': self.callback_code,
                'grant_type': 'authorization_code'
            }

            # Add code_verifier if PKCE was used
            if code_challenge and code_verifier:
                token_data['code_verifier'] = code_verifier

            print(f"[OAuth Client] Step 6: Exchanging code for token at {token_url}")

            response = http_request(
                'POST',
                token_url,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                data=urlencode(token_data)
            )

            if response.status_code != 200:
                print(f"[OAuth Client] Error exchanging code for token: {response.status_code}")
                print(f"[OAuth Client] Response: {response.text}")
                return None

            token_response = response.json()
            print(f"[OAuth Client] ✓ Successfully obtained access token!")

            return token_response

        finally:
            self.stop_callback_server()

    def test_token(self, token, faas_base_url):
        """
        Test if a token works by making an authenticated request.

        Args:
            token: Access token to test
            faas_base_url: Base URL of FaaS service

        Returns:
            True if token is valid, False otherwise
        """
        # Try to list versions (which requires authentication)
        # We need an account_id, which should be in the token payload
        # For testing, we'll just try to create a function

        from jose import jwt

        try:
            # Decode token (without verification, just to get account_id)
            payload = jwt.get_unverified_claims(token)
            account_id = payload.get('account_id')

            if not account_id:
                print("[OAuth Client] Error: No account_id in token")
                return False

            # Try to create a test function
            test_func_name = f'authtest{int(time.time())}'
            response = http_request(
                'POST',
                f'{faas_base_url}/accounts/{account_id}/workers/scripts/{test_func_name}/versions',
                headers={
                    'Host': 'func.local',
                    'Authorization': f'Bearer {token}'
                },
                files={
                    'metadata': (None, json.dumps({
                        'main_module': 'index.js',
                        'compatibility_date': '2025-01-01'
                    })),
                    'index.js': ('index.js', 'export default { async fetch() { return new Response("OK"); } }')
                }
            )

            if response.status_code == 200:
                print(f"[OAuth Client] ✓ Token is valid! Created test function: {test_func_name}")
                return True
            else:
                print(f"[OAuth Client] Token validation failed: {response.status_code}")
                return False

        except Exception as e:
            print(f"[OAuth Client] Error testing token: {e}")
            return False
