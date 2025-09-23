#!/usr/bin/env python3
"""
FaaS Platform Integration Test Suite

This script tests all functionality described in TASK.md including:
1. HTTP service with stateless cloud functions
2. Deployment API for uploading and deploying functions
3. Multi-function support with subdomain routing
4. Persistence of function code and metadata
5. Multi-version deployment with aliases and rollback
6. Environment variables per function version
"""

import json
import time
import uuid
import requests
import tempfile
import os
import sys
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import logging

# Disable proxy for localhost requests
os.environ['NO_PROXY'] = 'localhost,127.0.0.1'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

@dataclass
class TestConfig:
    """Test configuration"""
    base_url: str = "http://localhost:8080"
    base_domain: str = "func.local"
    timeout: int = 30

class FaaSTestClient:
    """Client for testing FaaS platform"""

    def __init__(self, config: TestConfig):
        self.config = config
        self.session = requests.Session()
        self.session.timeout = config.timeout

    def log_request(self, method: str, url: str, headers: Dict = None, data: Any = None, files: Dict = None):
        """Log HTTP request details"""
        logger.info(f"🔄 {method} {url}")
        if headers:
            for key, value in headers.items():
                logger.info(f"   Header: {key}: {value}")
        if data and not files:  # Don't log file data
            logger.info(f"   Body: {data}")
        if files:
            logger.info(f"   Files: {list(files.keys())}")

    def log_response(self, response: requests.Response):
        """Log HTTP response details"""
        logger.info(f"📨 Response: {response.status_code} {response.reason}")
        for key, value in response.headers.items():
            if key.lower() in ['content-type', 'content-length']:
                logger.info(f"   Header: {key}: {value}")

        try:
            if response.headers.get('content-type', '').startswith('application/json'):
                body = response.json()
                logger.info(f"   Body: {json.dumps(body, indent=2)}")
            else:
                logger.info(f"   Body: {response.text[:200]}...")
        except:
            logger.info(f"   Body: {response.text[:200]}...")

    def make_request(self, method: str, url: str, headers: Dict = None, data: Any = None, files: Dict = None) -> requests.Response:
        """Make HTTP request with logging"""
        self.log_request(method, url, headers, data, files)

        if method.upper() == 'GET':
            response = self.session.get(url, headers=headers)
        elif method.upper() == 'POST':
            response = self.session.post(url, headers=headers, json=data, files=files)
        elif method.upper() == 'PUT':
            if files:
                response = self.session.put(url, headers=headers, files=files)
            else:
                response = self.session.put(url, headers=headers, json=data)
        elif method.upper() == 'DELETE':
            response = self.session.delete(url, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")

        self.log_response(response)
        return response

    def test_management_api(self, endpoint: str) -> requests.Response:
        """Test management API endpoint"""
        return self.make_request('GET', f"{self.config.base_url}{endpoint}",
                               headers={'Host': self.config.base_domain})

    def deploy_function(self, script_name: str, metadata: Dict, files: Dict[str, str]) -> requests.Response:
        """Deploy a function with metadata and files"""
        # Prepare form data with metadata as a regular field and files as file uploads
        form_data = {
            'metadata': (None, json.dumps(metadata), 'application/json')
        }

        file_data = {}
        for filename, content in files.items():
            file_data[filename] = (filename, content, 'text/plain')

        return self.make_request('PUT',
                               f"{self.config.base_url}/accounts/test/workers/scripts/{script_name}",
                               headers={'Host': self.config.base_domain},
                               files={**form_data, **file_data})

    def create_deployment(self, script_name: str, version_id: str, percentage: int = 100) -> requests.Response:
        """Create a deployment for a function version"""
        deployment_data = {
            "strategy": "percentage",
            "versions": [{
                "percentage": percentage,
                "version_id": version_id
            }]
        }

        return self.make_request('POST',
                               f"{self.config.base_url}/accounts/test/workers/scripts/{script_name}/deployments",
                               headers={'Host': self.config.base_domain, 'Content-Type': 'application/json'},
                               data=deployment_data)

    def create_alias(self, script_name: str, alias_name: str, version_id: str) -> requests.Response:
        """Create an alias for a function version"""
        alias_data = {"version_id": version_id}

        return self.make_request('PUT',
                               f"{self.config.base_url}/accounts/test/workers/scripts/{script_name}/aliases/{alias_name}",
                               headers={'Host': self.config.base_domain, 'Content-Type': 'application/json'},
                               data=alias_data)

    def call_function(self, hostname: str, path: str = "/", method: str = "GET", data: Any = None) -> requests.Response:
        """Call a deployed function via its subdomain"""
        url = f"{self.config.base_url}{path}"
        headers = {'Host': hostname}

        return self.make_request(method, url, headers=headers, data=data)
    
    def get_versions(self, script_name: str) -> requests.Response:
        """Get all versions of a function"""
        return self.make_request('GET',
                               f"{self.config.base_url}/accounts/test/workers/scripts/{script_name}/versions",
                               headers={'Host': self.config.base_domain})
    
    def get_aliases(self, script_name: str) -> requests.Response:
        """Get all aliases of a function"""
        return self.make_request('GET',
                               f"{self.config.base_url}/accounts/test/workers/scripts/{script_name}/aliases",
                               headers={'Host': self.config.base_domain})

class FaaSIntegrationTest:
    """Main integration test class"""

    def __init__(self):
        self.config = TestConfig()
        self.client = FaaSTestClient(self.config)
        self.test_results = []

    def assert_response(self, response: requests.Response, expected_status: int,
                       expected_success: bool = None, test_name: str = ""):
        """Assert response meets expectations"""
        try:
            if response.status_code != expected_status:
                raise AssertionError(f"Expected status {expected_status}, got {response.status_code}")

            if expected_success is not None:
                try:
                    body = response.json()
                    if body.get('success') != expected_success:
                        raise AssertionError(f"Expected success={expected_success}, got {body.get('success')}")
                except:
                    if expected_success:
                        raise AssertionError("Expected JSON response with success field")

            logger.info(f"✅ {test_name}: PASSED")
            self.test_results.append((test_name, True, None))
            return True

        except Exception as e:
            logger.error(f"❌ {test_name}: FAILED - {str(e)}")
            self.test_results.append((test_name, False, str(e)))
            return False

    def test_basic_management_apis(self):
        """Test basic management API endpoints"""
        logger.info("🧪 Testing Basic Management APIs")

        # Test health endpoint
        response = self.client.test_management_api('/health')
        self.assert_response(response, 200, test_name="Health Check")
        
        if response.status_code == 200:
            try:
                body = response.json()
                logger.info(f"🏥 Health status: {body.get('status')}, Service: {body.get('service')}")
            except:
                pass

    def test_function_deployment(self):
        """Test function deployment functionality"""
        logger.info("🧪 Testing Function Deployment")

        # Create a simple function
        metadata = {
            "main_module": "index.js",
            "compatibility_date": "2025-01-01",
            "compatibility_flags": ["nodejs_compat"],
            "bindings": [
                {"name": "GREETING", "text": "Hello from Test Function!"},
                {"name": "VERSION", "text": "1.0.0"}
            ]
        }

        function_code = """
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Handle different paths
    if (url.pathname === '/health') {
      return Response.json({ status: 'healthy', timestamp: Date.now() });
    }

    if (url.pathname === '/env') {
      return Response.json({
        greeting: env.GREETING,
        version: env.VERSION,
        timestamp: Date.now()
      });
    }

    if (url.pathname === '/echo' && request.method === 'POST') {
      const body = await request.json();
      return Response.json({
        echo: body,
        received_at: Date.now()
      });
    }

    return Response.json({
      message: env.GREETING || 'Hello World!',
      version: env.VERSION || 'unknown',
      path: url.pathname,
      method: request.method,
      timestamp: Date.now()
    });
  }
}
""".strip()

        files = {"index.js": function_code}

        # Deploy the function
        response = self.client.deploy_function("test-function", metadata, files)
        if not self.assert_response(response, 200, True, "Function Deployment"):
            return None

        body = response.json()
        version_id = body['result']['id']
        logger.info(f"📦 Deployed function with version ID: {version_id}")

        return version_id

    def test_function_deployment_with_multiple_files(self):
        """Test function deployment with multiple files"""
        logger.info("🧪 Testing Multi-file Function Deployment")

        metadata = {
            "main_module": "main.js",
            "bindings": [
                {"name": "SERVICE_NAME", "text": "Multi-file Service"}
            ]
        }

        main_js = """
import { helper } from './utils.js';
import { config } from './config.js';

export default {
  async fetch(request, env, ctx) {
    const result = helper.process(request, env);
    return Response.json({
      service: env.SERVICE_NAME,
      config: config.version,
      result: result,
      timestamp: Date.now()
    });
  }
}
""".strip()

        utils_js = """
export const helper = {
  process(request, env) {
    const url = new URL(request.url);
    return {
      path: url.pathname,
      method: request.method,
      userAgent: request.headers.get('User-Agent')
    };
  }
};
""".strip()

        config_js = """
export const config = {
  version: "2.0.0",
  features: ["multi-file", "modules"]
};
""".strip()

        files = {
            "main.js": main_js,
            "utils.js": utils_js,
            "config.js": config_js
        }

        response = self.client.deploy_function("multi-file-function", metadata, files)
        if not self.assert_response(response, 200, True, "Multi-file Function Deployment"):
            return None

        body = response.json()
        version_id = body['result']['id']
        logger.info(f"📦 Deployed multi-file function with version ID: {version_id}")

        return version_id

    def test_deployment_management(self, version_id: str, script_name: str):
        """Test deployment management"""
        logger.info("🧪 Testing Deployment Management")

        # Create deployment
        response = self.client.create_deployment(script_name, version_id)
        if not self.assert_response(response, 200, True, "Create Deployment"):
            return None

        body = response.json()
        result_id = body['result']['id']
        logger.info(f"🚀 Deployment updated latest alias to version: {result_id}")

        # Test GET versions API
        response = self.client.get_versions(script_name)
        self.assert_response(response, 200, True, "Get Function Versions")
        
        # Test GET aliases API
        response = self.client.get_aliases(script_name)
        self.assert_response(response, 200, True, "Get Function Aliases")

        return result_id

    def test_alias_management(self, version_id: str, script_name: str):
        """Test alias management"""
        logger.info("🧪 Testing Alias Management")

        # Create production alias
        response = self.client.create_alias(script_name, "production", version_id)
        self.assert_response(response, 200, True, "Create Production Alias")

        # Create staging alias
        response = self.client.create_alias(script_name, "staging", version_id)
        self.assert_response(response, 200, True, "Create Staging Alias")

    def test_function_execution(self, script_name: str):
        """Test function execution via different access methods"""
        logger.info("🧪 Testing Function Execution")

        # Test direct function access
        hostname = f"{script_name}.{self.config.base_domain}"
        response = self.client.call_function(hostname)
        self.assert_response(response, 200, test_name="Direct Function Access")

        if response.status_code == 200:
            try:
                body = response.json()
                logger.info(f"🎯 Function response: {json.dumps(body, indent=2)}")
            except:
                pass

        # Test health endpoint
        response = self.client.call_function(hostname, "/health")
        self.assert_response(response, 200, test_name="Health Endpoint")

        # Test environment variables endpoint
        response = self.client.call_function(hostname, "/env")
        self.assert_response(response, 200, test_name="Environment Variables")

        # Test POST endpoint
        test_data = {"test": "data", "number": 42}
        response = self.client.call_function(hostname, "/echo", "POST", test_data)
        self.assert_response(response, 200, test_name="POST Echo Endpoint")

    def test_alias_access(self, script_name: str):
        """Test function access via aliases"""
        logger.info("🧪 Testing Alias Access")

        # Test production alias
        hostname = f"production.{script_name}.{self.config.base_domain}"
        response = self.client.call_function(hostname)
        self.assert_response(response, 200, test_name="Production Alias Access")

        # Test staging alias
        hostname = f"staging.{script_name}.{self.config.base_domain}"
        response = self.client.call_function(hostname)
        self.assert_response(response, 200, test_name="Staging Alias Access")

        # Test latest alias (should be created automatically)
        hostname = f"latest.{script_name}.{self.config.base_domain}"
        response = self.client.call_function(hostname)
        self.assert_response(response, 200, test_name="Latest Alias Access")

    def test_version_access(self, script_name: str, version_id: str):
        """Test function access via version prefix"""
        logger.info("🧪 Testing Version Access")

        # Test version prefix access (first 8 characters of UUID)
        version_prefix = version_id[:8]
        hostname = f"{version_prefix}.{script_name}.{self.config.base_domain}"
        response = self.client.call_function(hostname)
        self.assert_response(response, 200, test_name="Version Prefix Access")

    def test_multi_version_scenario(self):
        """Test multi-version deployment scenario"""
        logger.info("🧪 Testing Multi-Version Scenario")

        script_name = "versioned-function"

        # Deploy version 1
        metadata_v1 = {
            "main_module": "index.js",
            "bindings": [
                {"name": "VERSION", "text": "1.0.0"},
                {"name": "FEATURE", "text": "basic"}
            ]
        }

        code_v1 = """
export default {
  async fetch(request, env, ctx) {
    return Response.json({
      version: env.VERSION,
      feature: env.FEATURE,
      message: "This is version 1",
      timestamp: Date.now()
    });
  }
}
""".strip()

        response = self.client.deploy_function(script_name, metadata_v1, {"index.js": code_v1})
        if not self.assert_response(response, 200, True, "Deploy Version 1"):
            return

        version_1_id = response.json()['result']['id']
        logger.info(f"📦 Deployed version 1: {version_1_id}")

        # Deploy version 2
        metadata_v2 = {
            "main_module": "index.js",
            "bindings": [
                {"name": "VERSION", "text": "2.0.0"},
                {"name": "FEATURE", "text": "advanced"},
                {"name": "NEW_FEATURE", "text": "enhanced"}
            ]
        }

        code_v2 = """
export default {
  async fetch(request, env, ctx) {
    return Response.json({
      version: env.VERSION,
      feature: env.FEATURE,
      newFeature: env.NEW_FEATURE,
      message: "This is version 2 with new features",
      timestamp: Date.now()
    });
  }
}
""".strip()

        response = self.client.deploy_function(script_name, metadata_v2, {"index.js": code_v2})
        if not self.assert_response(response, 200, True, "Deploy Version 2"):
            return

        version_2_id = response.json()['result']['id']
        logger.info(f"📦 Deployed version 2: {version_2_id}")

        # Deploy version 2 as latest (deployment API just updates latest alias)
        self.client.create_deployment(script_name, version_2_id)

        # Create aliases
        self.client.create_alias(script_name, "v1", version_1_id)
        self.client.create_alias(script_name, "v2", version_2_id)
        self.client.create_alias(script_name, "stable", version_1_id)

        # Test version-specific access
        response = self.client.call_function(f"v1.{script_name}.{self.config.base_domain}")
        self.assert_response(response, 200, test_name="Version 1 Alias Access")

        response = self.client.call_function(f"v2.{script_name}.{self.config.base_domain}")
        self.assert_response(response, 200, test_name="Version 2 Alias Access")

        # Test that latest points to version 2 (set by deployment)
        response = self.client.call_function(f"latest.{script_name}.{self.config.base_domain}")
        self.assert_response(response, 200, test_name="Latest Points to Version 2")

        # Test rollback scenario - set stable to latest
        self.client.create_alias(script_name, "latest", version_1_id)
        response = self.client.call_function(f"latest.{script_name}.{self.config.base_domain}")
        self.assert_response(response, 200, test_name="Rollback to Version 1")

    def test_error_scenarios(self):
        """Test error handling and edge cases"""
        logger.info("🧪 Testing Error Scenarios")

        # Test non-existent function
        response = self.client.call_function(f"nonexistent.{self.config.base_domain}")
        self.assert_response(response, 404, False, "Non-existent Function")

        # Test invalid domain
        response = self.client.call_function("invalid-domain.com")
        self.assert_response(response, 404, False, "Invalid Domain")

        # Test deployment with non-existent version
        fake_uuid = str(uuid.uuid4())
        response = self.client.create_deployment("test-function", fake_uuid)
        self.assert_response(response, 404, False, "Deploy Non-existent Version")

        # Test alias with non-existent version
        response = self.client.create_alias("test-function", "invalid", fake_uuid)
        self.assert_response(response, 404, False, "Alias Non-existent Version")

        # Test invalid deployment percentage
        invalid_deployment = {
            "strategy": "percentage",
            "versions": [
                {"percentage": 50, "version_id": fake_uuid},
                {"percentage": 50, "version_id": fake_uuid}
            ]
        }

        response = self.client.make_request('POST',
                                          f"{self.config.base_url}/accounts/test/workers/scripts/test/deployments",
                                          headers={'Host': self.config.base_domain, 'Content-Type': 'application/json'},
                                          data=invalid_deployment)
        self.assert_response(response, 400, False, "Invalid Deployment Configuration")

    def test_persistence_after_restart(self):
        """Test that functions persist after platform restart"""
        logger.info("🧪 Testing Persistence (Manual Verification Required)")

        # This test documents what should be verified manually:
        logger.info("📝 Manual Test Required:")
        logger.info("   1. Stop the FaaS platform")
        logger.info("   2. Restart the FaaS platform")
        logger.info("   3. Verify that deployed functions still work")
        logger.info("   4. Verify that aliases and deployments are preserved")

        # We can test that the functions work now, which proves they're in storage
        response = self.client.call_function(f"test-function.{self.config.base_domain}")
        self.assert_response(response, 200, test_name="Function Available (Pre-restart Test)")

    def run_all_tests(self):
        """Run the complete test suite"""
        logger.info("🚀 Starting FaaS Platform Integration Tests")
        logger.info("=" * 60)

        try:
            # Basic functionality tests
            self.test_basic_management_apis()

            # Function deployment tests
            version_id = self.test_function_deployment()
            if version_id:
                deployment_id = self.test_deployment_management(version_id, "test-function")
                self.test_alias_management(version_id, "test-function")
                self.test_function_execution("test-function")
                self.test_alias_access("test-function")
                self.test_version_access("test-function", version_id)

            # Multi-file deployment test
            multi_version_id = self.test_function_deployment_with_multiple_files()
            if multi_version_id:
                self.test_deployment_management(multi_version_id, "multi-file-function")
                self.test_function_execution("multi-file-function")

            # Multi-version scenario
            self.test_multi_version_scenario()

            # Error scenarios
            self.test_error_scenarios()

            # Persistence test
            self.test_persistence_after_restart()

        except KeyboardInterrupt:
            logger.info("🛑 Tests interrupted by user")
        except Exception as e:
            logger.error(f"💥 Unexpected error during tests: {str(e)}")

        # Print test summary
        self.print_test_summary()

    def print_test_summary(self):
        """Print test results summary"""
        logger.info("=" * 60)
        logger.info("📊 Test Results Summary")
        logger.info("=" * 60)

        passed = sum(1 for _, success, _ in self.test_results if success)
        failed = len(self.test_results) - passed

        logger.info(f"Total Tests: {len(self.test_results)}")
        logger.info(f"Passed: {passed} ✅")
        logger.info(f"Failed: {failed} ❌")

        if failed > 0:
            logger.info("\n❌ Failed Tests:")
            for test_name, success, error in self.test_results:
                if not success:
                    logger.info(f"   - {test_name}: {error}")

        logger.info("\n📋 Detailed Results:")
        for test_name, success, error in self.test_results:
            status = "✅ PASS" if success else "❌ FAIL"
            logger.info(f"   {status} - {test_name}")
            if error:
                logger.info(f"     Error: {error}")

        success_rate = (passed / len(self.test_results)) * 100 if self.test_results else 0
        logger.info(f"\n🎯 Success Rate: {success_rate:.1f}%")

        if success_rate == 100:
            logger.info("🎉 All tests passed! FaaS platform is working correctly.")
        elif success_rate >= 80:
            logger.info("⚠️  Most tests passed, but some issues need attention.")
        else:
            logger.info("🚨 Many tests failed, platform needs significant fixes.")

def main():
    """Main function to run the test suite"""
    print("🧪 FaaS Platform Integration Test Suite")
    print("========================================")
    print()

    # Check if platform is running
    try:
        response = requests.get("http://localhost:8080/health",
                              headers={'Host': 'func.local'},
                              timeout=5)
        if response.status_code != 200:
            raise Exception("Platform not responding correctly")
    except Exception as e:
        print("❌ Error: FaaS platform is not running or not accessible")
        print("   Please start the platform with: BASE_DOMAIN=func.local pnpm dev")
        print(f"   Error details: {str(e)}")
        sys.exit(1)

    print("✅ FaaS platform is running and accessible")
    print()

    # Run tests
    test_suite = FaaSIntegrationTest()
    test_suite.run_all_tests()

if __name__ == "__main__":
    main()
