"""Function lifecycle tests."""

import json
from framework import TestSuite
from helpers import create_and_deploy_function, http_request
from config import FAAS_BASE_URL, FAAS_HOST


def create_function_suite():
    """Create function lifecycle test suite."""
    suite = TestSuite("Function Lifecycle Tests")

    def test_function_with_env_vars(ctx):
        """Function with environment variables"""
        script = """
        export default {
            async fetch(request, env) {
                return Response.json({
                    greeting: env.GREETING,
                    version: env.VERSION
                });
            }
        }
        """

        metadata = {
            'main_module': 'index.js',
            'compatibility_date': '2025-01-01',
            'bindings': [
                {'name': 'GREETING', 'text': 'Hello!'},
                {'name': 'VERSION', 'text': '1.0.0'}
            ]
        }

        _, deploy_resp, _ = create_and_deploy_function(
            'envtest', script, ctx.account_id, ctx.user_token,
            FAAS_BASE_URL, FAAS_HOST, metadata
        )

        assert deploy_resp.status_code == 200

        # Test function
        response = http_request('GET', f'{FAAS_BASE_URL}/', headers={'Host': f'envtest.{FAAS_HOST}'})
        assert response.status_code == 200
        data = response.json()
        assert data['greeting'] == 'Hello!'
        assert data['version'] == '1.0.0'

        print("✓ Function with environment variables works")

    def test_multiple_modules(ctx):
        """Function with multiple modules"""
        main_script = """
        import { greet } from './utils.js';
        export default {
            async fetch(request) {
                return new Response(greet('World'));
            }
        }
        """

        utils_script = """
        export function greet(name) {
            return 'Hello, ' + name + '!';
        }
        """

        response = http_request(
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/multimodule',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}',
            },
            files={
                'metadata': (None, json.dumps({
                    'main_module': 'index.js',
                    'compatibility_date': '2025-01-01'
                })),
                'index.js': ('index.js', main_script),
                'utils.js': ('utils.js', utils_script)
            }
        )
        assert response.status_code == 200
        version_id = response.json()['result']['id']

        # Deploy
        from helpers import deploy_function
        deploy_resp = deploy_function(
            'multimodule', version_id, ctx.account_id, ctx.user_token,
            FAAS_BASE_URL, FAAS_HOST
        )
        assert deploy_resp.status_code == 200

        import time
        time.sleep(0.5)

        # Test
        response = http_request('GET', f'{FAAS_BASE_URL}/', headers={'Host': f'multimodule.{FAAS_HOST}'})
        assert response.status_code == 200
        assert response.text == 'Hello, World!'

        print("✓ Multiple modules work correctly")

    def test_invalid_metadata(ctx):
        """Invalid metadata handling"""
        # Missing main_module
        response = http_request(
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/invalid',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}',
            },
            files={
                'metadata': (None, json.dumps({'compatibility_date': '2025-01-01'})),
                'index.js': ('index.js', 'export default {}')
            }
        )
        assert response.status_code == 400

        print("✓ Invalid metadata rejected")

    suite.add_test(test_function_with_env_vars)
    suite.add_test(test_multiple_modules)
    suite.add_test(test_invalid_metadata)

    return suite
