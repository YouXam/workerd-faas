"""Test configuration."""

# API Configuration
FAAS_BASE_URL = "http://localhost:8080"
FAAS_HOST = "func.local"
JWT_SECRET = "test-secret-key-for-integration-tests"

# Mock OIDC Configuration
MOCK_OIDC_PORT = 9999

# Test timeouts
DEFAULT_WAIT_TIME = 0.5  # seconds to wait after deployment
REQUEST_TIMEOUT = 10  # seconds
