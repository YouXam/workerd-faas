"""Mock OIDC Provider for testing."""

import json
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse, urlencode
from threading import Thread


class MockOIDCProvider:
    """Mock OIDC Provider that implements OAuth2/OIDC endpoints."""

    def __init__(self, port=9999):
        self.port = port
        self.server = None
        self.thread = None

        # Storage
        self.users = {
            'testuser': {
                'sub': 'test-user-id-123',
                'email': 'testuser@example.com',
                'preferred_username': 'testuser',
                'name': 'Test User',
                'email_verified': True
            }
        }
        self.authorization_codes = {}  # code -> user_info
        self.access_tokens = {}  # token -> user_info
        self.id_tokens = {}  # token -> user_info

    def start(self):
        """Start the mock OIDC server."""
        handler = self._create_handler()
        self.server = HTTPServer(('localhost', self.port), handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop the mock OIDC server."""
        if self.server:
            self.server.shutdown()
            self.server = None
            self.thread = None

    def _create_handler(self):
        """Create request handler with access to provider instance."""
        provider = self

        class MockOIDCHandler(BaseHTTPRequestHandler):
            """HTTP request handler for mock OIDC provider."""

            def log_message(self, format, *args):
                """Suppress log messages."""
                pass

            def do_GET(self):
                """Handle GET requests."""
                parsed_url = urlparse(self.path)
                path = parsed_url.path
                params = parse_qs(parsed_url.query)

                if path == '/.well-known/openid-configuration':
                    self._handle_discovery()
                elif path == '/authorize':
                    self._handle_authorization(params)
                elif path == '/userinfo':
                    self._handle_userinfo()
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b'Not Found')

            def do_POST(self):
                """Handle POST requests."""
                parsed_url = urlparse(self.path)
                path = parsed_url.path

                if path == '/token':
                    content_length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(content_length).decode('utf-8')
                    params = parse_qs(body)
                    self._handle_token(params)
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b'Not Found')

            def _handle_discovery(self):
                """Handle OIDC discovery endpoint."""
                base_url = f'http://localhost:{provider.port}'
                discovery = {
                    'issuer': base_url,
                    'authorization_endpoint': f'{base_url}/authorize',
                    'token_endpoint': f'{base_url}/token',
                    'userinfo_endpoint': f'{base_url}/userinfo',
                    'jwks_uri': f'{base_url}/jwks',
                    'response_types_supported': ['code'],
                    'subject_types_supported': ['public'],
                    'id_token_signing_alg_values_supported': ['RS256'],
                    'scopes_supported': ['openid', 'profile', 'email'],
                    'token_endpoint_auth_methods_supported': ['client_secret_post', 'client_secret_basic'],
                    'claims_supported': ['sub', 'email', 'preferred_username', 'name']
                }

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(discovery).encode())

            def _handle_authorization(self, params):
                """Handle OAuth2 authorization endpoint."""
                client_id = params.get('client_id', [''])[0]
                redirect_uri = params.get('redirect_uri', [''])[0]
                state = params.get('state', [''])[0]
                scope = params.get('scope', [''])[0]
                response_type = params.get('response_type', [''])[0]

                if not client_id or not redirect_uri or response_type != 'code':
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'Invalid request')
                    return

                # Auto-approve for test user
                code = f'test-auth-code-{uuid.uuid4().hex[:16]}'
                user_info = provider.users['testuser']

                # Store authorization code
                provider.authorization_codes[code] = {
                    'user_info': user_info,
                    'client_id': client_id,
                    'redirect_uri': redirect_uri,
                    'expires_at': time.time() + 300  # 5 minutes
                }

                # Redirect back to client with code
                redirect_params = {'code': code}
                if state:
                    redirect_params['state'] = state

                redirect_url = f'{redirect_uri}?{urlencode(redirect_params)}'

                self.send_response(302)
                self.send_header('Location', redirect_url)
                self.end_headers()

            def _handle_token(self, params):
                """Handle OAuth2 token endpoint."""
                grant_type = params.get('grant_type', [''])[0]
                code = params.get('code', [''])[0]
                client_id = params.get('client_id', [''])[0]
                client_secret = params.get('client_secret', [''])[0]
                redirect_uri = params.get('redirect_uri', [''])[0]

                if grant_type != 'authorization_code':
                    self._send_json({'error': 'unsupported_grant_type'}, 400)
                    return

                if code not in provider.authorization_codes:
                    self._send_json({'error': 'invalid_grant'}, 400)
                    return

                code_data = provider.authorization_codes[code]

                # Verify code hasn't expired
                if time.time() > code_data['expires_at']:
                    del provider.authorization_codes[code]
                    self._send_json({'error': 'invalid_grant'}, 400)
                    return

                # Verify client and redirect URI match
                if code_data['client_id'] != client_id or code_data['redirect_uri'] != redirect_uri:
                    self._send_json({'error': 'invalid_grant'}, 400)
                    return

                # Generate tokens
                access_token = f'test-access-token-{uuid.uuid4().hex[:16]}'
                id_token = f'test-id-token-{uuid.uuid4().hex[:16]}'

                user_info = code_data['user_info']
                provider.access_tokens[access_token] = {
                    'user_info': user_info,
                    'expires_at': time.time() + 3600
                }
                provider.id_tokens[id_token] = user_info

                # Consume authorization code
                del provider.authorization_codes[code]

                response = {
                    'access_token': access_token,
                    'token_type': 'Bearer',
                    'expires_in': 3600,
                    'id_token': id_token,
                    'scope': 'openid profile email'
                }

                self._send_json(response, 200)

            def _handle_userinfo(self):
                """Handle OIDC userinfo endpoint."""
                auth_header = self.headers.get('Authorization', '')

                if not auth_header.startswith('Bearer '):
                    self._send_json({'error': 'invalid_token'}, 401)
                    return

                access_token = auth_header[7:]  # Remove "Bearer "

                if access_token not in provider.access_tokens:
                    self._send_json({'error': 'invalid_token'}, 401)
                    return

                token_data = provider.access_tokens[access_token]

                # Check if token expired
                if time.time() > token_data['expires_at']:
                    del provider.access_tokens[access_token]
                    self._send_json({'error': 'invalid_token'}, 401)
                    return

                self._send_json(token_data['user_info'], 200)

            def _send_json(self, data, status=200):
                """Send JSON response."""
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

        return MockOIDCHandler
