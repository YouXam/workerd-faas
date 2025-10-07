"""Base classes for test framework."""

import time
from typing import Optional, Callable


class TestCase:
    """Base class for test cases."""

    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.error: Optional[Exception] = None

    def setup(self):
        """Setup method called before each test."""
        pass

    def teardown(self):
        """Teardown method called after each test."""
        pass

    def run(self):
        """Run the test case."""
        raise NotImplementedError("Test cases must implement run()")

    def assert_equal(self, actual, expected, message=""):
        """Assert that two values are equal."""
        if actual != expected:
            raise AssertionError(
                f"{message}\nExpected: {expected}\nActual: {actual}"
            )

    def assert_true(self, condition, message=""):
        """Assert that condition is true."""
        if not condition:
            raise AssertionError(message or "Condition is not true")

    def assert_in(self, item, container, message=""):
        """Assert that item is in container."""
        if item not in container:
            raise AssertionError(
                message or f"{item} not found in {container}"
            )

    def assert_status_code(self, response, expected_code, message=""):
        """Assert HTTP response status code."""
        if response.status_code != expected_code:
            raise AssertionError(
                f"{message}\nExpected status: {expected_code}\n"
                f"Actual status: {response.status_code}\n"
                f"Response: {response.text}"
            )


class TestSuite:
    """A collection of test cases."""

    def __init__(self, name: str):
        self.name = name
        self.tests: list[Callable] = []
        self.setup_func: Optional[Callable] = None
        self.teardown_func: Optional[Callable] = None

    def add_test(self, test_func: Callable, name: str = None):
        """Add a test function to the suite."""
        if name:
            test_func.__name__ = name
        self.tests.append(test_func)

    def setup(self, func: Callable):
        """Set the setup function for this suite."""
        self.setup_func = func
        return func

    def teardown(self, func: Callable):
        """Set the teardown function for this suite."""
        self.teardown_func = func
        return func

    def run_all(self, context=None) -> tuple[int, int]:
        """
        Run all tests in the suite.
        Returns (passed_count, total_count).
        """
        if self.setup_func and context:
            self.setup_func(context)

        passed = 0
        total = len(self.tests)

        print(f"\n{'='*60}")
        print(f"Running {self.name}")
        print('='*60)

        for test_func in self.tests:
            test_name = test_func.__name__.replace('_', ' ').title()
            print(f"\n[TEST] {test_name}")

            try:
                if context:
                    test_func(context)
                else:
                    test_func()
                print(f"✓ {test_name} passed")
                passed += 1
            except Exception as e:
                print(f"✗ {test_name} failed: {e}")
                import traceback
                traceback.print_exc()

        if self.teardown_func and context:
            self.teardown_func(context)

        return passed, total
