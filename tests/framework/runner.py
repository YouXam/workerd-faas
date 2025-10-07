"""Test runner for executing test suites."""

from typing import List
from .base import TestSuite


class TestRunner:
    """Main test runner that executes multiple test suites."""

    def __init__(self):
        self.suites: List[TestSuite] = []
        self.setup_func = None
        self.teardown_func = None

    def add_suite(self, suite: TestSuite):
        """Add a test suite to the runner."""
        self.suites.append(suite)

    def global_setup(self, func):
        """Set global setup function."""
        self.setup_func = func
        return func

    def global_teardown(self, func):
        """Set global teardown function."""
        self.teardown_func = func
        return func

    def run(self, context=None) -> bool:
        """
        Run all test suites.
        Returns True if all tests passed, False otherwise.
        """
        if self.setup_func:
            print("Setting up test environment...")
            self.setup_func()

        total_passed = 0
        total_tests = 0

        for suite in self.suites:
            passed, total = suite.run_all(context)
            total_passed += passed
            total_tests += total

        if self.teardown_func:
            print("\nCleaning up...")
            self.teardown_func()

        print(f"\n{'='*60}")
        if total_passed == total_tests:
            print(f"✅ All {total_tests} tests passed!")
        else:
            print(f"❌ {total_tests - total_passed} of {total_tests} tests failed")
        print('='*60)

        return total_passed == total_tests
