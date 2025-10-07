"""Test context for sharing state across tests."""

import subprocess
import shutil
import time
import os
from pathlib import Path

from config import MOCK_OIDC_PORT, FAAS_BASE_URL, FAAS_HOST
from helpers import generate_test_token, http_request, MockOIDCProvider


class TestContext:
    """Shared context for all tests."""

    def __init__(self):
        self.oidc_provider = None
        self.faas_process = None
        self.log_file = None

        # Authentication
        self.user_token = None
        self.account_id = None
        self.username = "testuser"
        self.email = "testuser@example.com"

    def start_mock_oidc(self):
        """Start mock OIDC server."""
        self.oidc_provider = MockOIDCProvider(port=MOCK_OIDC_PORT)
        self.oidc_provider.start()
        print(f"✓ Mock OIDC server started on port {MOCK_OIDC_PORT}")

    def stop_mock_oidc(self):
        """Stop mock OIDC server."""
        if self.oidc_provider:
            self.oidc_provider.stop()
            self.oidc_provider = None

    def build_faas(self):
        """Build the FaaS service."""
        print("Building FaaS service...")

        # Set environment variables for build
        env = os.environ.copy()
        env['BASE_DOMAIN'] = FAAS_HOST

        result = subprocess.run(
            ['pnpm', 'exec', 'wrangler', 'build'],
            cwd=Path(__file__).parent.parent,
            env=env,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise RuntimeError(f"Build failed: {result.stderr}")
        print("✓ Build completed")

    def start_faas(self):
        """Start the FaaS service."""
        # Clean up old data
        data_dir = Path(__file__).parent.parent / 'data'
        if data_dir.exists():
            shutil.rmtree(data_dir)
        data_dir.mkdir(exist_ok=True)
        (data_dir / 'do').mkdir(exist_ok=True)
        (data_dir / 'files').mkdir(exist_ok=True)

        # Start workerd - prefer ~/.local/bin/workerd over npm wrapper
        workerd_path = os.path.expanduser('~/.local/bin/workerd')
        if not os.path.exists(workerd_path):
            workerd_path = shutil.which('workerd')

        if not workerd_path:
            raise RuntimeError("workerd not found in PATH or ~/.local/bin/")

        print(f"Starting workerd from: {workerd_path}")

        # Use absolute path for log file
        log_path = Path(__file__).parent.parent / 'faas_test.log'
        self.log_file = open(log_path, 'w')

        # Set environment variables needed by workerd (use 127.0.0.1 for OIDC)
        env = os.environ.copy()
        env['BASE_DOMAIN'] = FAAS_HOST
        env['JWT_SECRET'] = 'test-secret-key-for-integration-tests'
        env['OIDC_ISSUER'] = f'http://127.0.0.1:{MOCK_OIDC_PORT}'
        env['OIDC_AUTHORIZATION_ENDPOINT'] = f'http://127.0.0.1:{MOCK_OIDC_PORT}/authorize'
        env['OIDC_TOKEN_ENDPOINT'] = f'http://127.0.0.1:{MOCK_OIDC_PORT}/token'
        env['OIDC_USERINFO_ENDPOINT'] = f'http://127.0.0.1:{MOCK_OIDC_PORT}/userinfo'
        env['OIDC_CLIENT_ID'] = 'test-client'
        env['OIDC_CLIENT_SECRET'] = 'test-secret'
        env['OIDC_REDIRECT_URI'] = f'{FAAS_BASE_URL}/auth/callback'

        # Start workerd from project root directory
        project_root = Path(__file__).parent.parent
        self.faas_process = subprocess.Popen(
            [workerd_path, 'serve', 'config.capnp', '--experimental'],
            cwd=str(project_root),
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env
        )

        # Wait for service to be ready
        print(f"Waiting for FaaS service to start (checking {FAAS_BASE_URL}/health)...")
        time.sleep(3)  # Initial wait

        # Check if process is still running
        log_path = Path(__file__).parent.parent / 'faas_test.log'
        if self.faas_process.poll() is not None:
            self.log_file.close()
            with open(log_path, 'r') as f:
                log_content = f.read()
            raise RuntimeError(f"FaaS service exited immediately. Exit code: {self.faas_process.returncode}\nLog:\n{log_content}")

        if not self.wait_for_server(f'{FAAS_BASE_URL}/health'):
            # Print last lines of log
            self.log_file.close()
            with open(log_path, 'r') as f:
                lines = f.readlines()
                print("\nLast 20 lines of faas_test.log:")
                for line in lines[-20:]:
                    print(line.rstrip())
            raise RuntimeError("FaaS service failed to start")

        print("✓ FaaS service is ready")

    def stop_faas(self):
        """Stop the FaaS service."""
        if self.faas_process:
            self.faas_process.terminate()
            try:
                self.faas_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.faas_process.kill()
            self.faas_process = None

        if self.log_file:
            self.log_file.close()
            self.log_file = None

    def wait_for_server(self, url, max_attempts=60, wait_interval=0.5):
        """Wait for server to be ready."""
        for _ in range(max_attempts):
            try:
                response = http_request('GET', url)
                if response.status_code == 200:
                    return True
                else:
                    print(f"Waiting for server... (status code: {response.status_code})")
            except Exception as e:
                pass
            time.sleep(wait_interval)
        return False

    def generate_token(self):
        """Generate authentication token for tests."""
        self.user_token, self.account_id, _ = generate_test_token(
            username=self.username,
            email=self.email
        )
        print(f"✓ Generated test token for account {self.account_id}")

    def setup(self):
        """Setup test environment."""
        self.start_mock_oidc()
        self.build_faas()
        self.start_faas()
        self.generate_token()

    def teardown(self):
        """Teardown test environment."""
        self.stop_faas()
        self.stop_mock_oidc()
        print("✓ Cleanup complete")
