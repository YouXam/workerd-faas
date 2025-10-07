#!/usr/bin/env python3
"""
Main test runner for FaaS integration tests.

Usage:
    python3 tests/run_tests.py
    python3 tests/run_tests.py --suite auth
    python3 tests/run_tests.py --suite function
"""

import sys
import argparse
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from framework import TestRunner
from context import TestContext
from suites import (
    create_auth_suite,
    create_function_suite,
    create_version_suite,
    create_runtime_suite,
    create_oidc_flow_suite
)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Run FaaS integration tests')
    parser.add_argument(
        '--suite',
        choices=['oidc', 'auth', 'function', 'version', 'runtime', 'all'],
        default='all',
        help='Test suite to run (default: all)'
    )
    args = parser.parse_args()

    # Create test context
    ctx = TestContext()

    # Create test runner
    runner = TestRunner()

    # Add test suites based on arguments
    # OIDC flow tests should run first as they test the complete authentication
    if args.suite == 'all' or args.suite == 'oidc':
        runner.add_suite(create_oidc_flow_suite())

    if args.suite == 'all' or args.suite == 'auth':
        runner.add_suite(create_auth_suite())

    if args.suite == 'all' or args.suite == 'function':
        runner.add_suite(create_function_suite())

    if args.suite == 'all' or args.suite == 'version':
        runner.add_suite(create_version_suite())

    if args.suite == 'all' or args.suite == 'runtime':
        runner.add_suite(create_runtime_suite())

    # Setup and teardown (no arguments for global setup/teardown)
    def setup():
        ctx.setup()

    def teardown():
        ctx.teardown()

    runner.global_setup(setup)
    runner.global_teardown(teardown)

    # Run tests
    try:
        success = runner.run(ctx)
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        ctx.teardown()
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        ctx.teardown()
        sys.exit(1)


if __name__ == '__main__':
    main()
