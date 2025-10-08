"""Test suites for FaaS integration tests."""

from .auth_tests import create_auth_suite
from .function_tests import create_function_suite
from .version_tests import create_version_suite
from .runtime_tests import create_runtime_suite
from .oidc_flow_tests import create_oidc_flow_suite
from .pkce_tests import create_pkce_suite

__all__ = [
    'create_auth_suite',
    'create_function_suite',
    'create_version_suite',
    'create_runtime_suite',
    'create_oidc_flow_suite',
    'create_pkce_suite'
]
