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
            'POST',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/multimodule/versions',
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
        time.sleep(0.1)

        # Test
        response = http_request('GET', f'{FAAS_BASE_URL}/', headers={'Host': f'multimodule.{FAAS_HOST}'})
        assert response.status_code == 200
        assert response.text == 'Hello, World!'

        print("✓ Multiple modules work correctly")

    def test_invalid_metadata(ctx):
        """Invalid metadata handling"""
        # Missing main_module
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/invalid/versions',
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

    def test_function_with_fetch_request(ctx):
        """Function making external HTTP requests"""
        script = """
        export default {
            async fetch(request) {
                // Echo back the request method and URL
                return Response.json({
                    method: request.method,
                    url: request.url,
                    headers: Object.fromEntries(request.headers)
                });
            }
        }
        """

        _, deploy_resp, _ = create_and_deploy_function(
            'fetchtest', script, ctx.account_id, ctx.user_token,
            FAAS_BASE_URL, FAAS_HOST
        )
        assert deploy_resp.status_code == 200

        # Test POST with body
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/api/test',
            headers={
                'Host': f'fetchtest.{FAAS_HOST}',
                'Content-Type': 'application/json'
            },
            data=json.dumps({'test': 'data'})
        )
        assert response.status_code == 200
        data = response.json()
        assert data['method'] == 'POST'
        assert 'content-type' in data['headers']

        print("✓ Function handles HTTP requests correctly")

    def test_function_response_types(ctx):
        """Function with different response types"""
        script = """
        export default {
            async fetch(request) {
                const url = new URL(request.url);
                const type = url.searchParams.get('type');

                switch(type) {
                    case 'json':
                        return Response.json({success: true});
                    case 'text':
                        return new Response('Hello, World!', {
                            headers: {'Content-Type': 'text/plain'}
                        });
                    case 'html':
                        return new Response('<h1>Hello</h1>', {
                            headers: {'Content-Type': 'text/html'}
                        });
                    case 'redirect':
                        return Response.redirect('https://example.com', 302);
                    case 'error':
                        return new Response('Not Found', {status: 404});
                    default:
                        return new Response('OK');
                }
            }
        }
        """

        _, deploy_resp, _ = create_and_deploy_function(
            'responsetest', script, ctx.account_id, ctx.user_token,
            FAAS_BASE_URL, FAAS_HOST
        )
        assert deploy_resp.status_code == 200

        # Test JSON response
        resp = http_request('GET', f'{FAAS_BASE_URL}/?type=json',
                           headers={'Host': f'responsetest.{FAAS_HOST}'})
        assert resp.status_code == 200
        assert resp.json()['success'] == True

        # Test text response
        resp = http_request('GET', f'{FAAS_BASE_URL}/?type=text',
                           headers={'Host': f'responsetest.{FAAS_HOST}'})
        assert resp.status_code == 200
        assert resp.text == 'Hello, World!'

        # Test HTML response
        resp = http_request('GET', f'{FAAS_BASE_URL}/?type=html',
                           headers={'Host': f'responsetest.{FAAS_HOST}'})
        assert resp.status_code == 200
        assert '<h1>Hello</h1>' in resp.text

        # Test redirect
        resp = http_request('GET', f'{FAAS_BASE_URL}/?type=redirect',
                           headers={'Host': f'responsetest.{FAAS_HOST}'},
                           allow_redirects=False)
        assert resp.status_code == 302

        # Test error response
        resp = http_request('GET', f'{FAAS_BASE_URL}/?type=error',
                           headers={'Host': f'responsetest.{FAAS_HOST}'})
        assert resp.status_code == 404

        print("✓ Function handles different response types")

    def test_function_with_large_payload(ctx):
        """Function handling large request/response payloads"""
        script = """
        export default {
            async fetch(request) {
                if (request.method === 'POST') {
                    const body = await request.text();
                    return Response.json({
                        received: body.length,
                        echo: body.substring(0, 100)
                    });
                }
                // Return large response
                const largeData = 'x'.repeat(100000);
                return new Response(largeData);
            }
        }
        """

        _, deploy_resp, _ = create_and_deploy_function(
            'largetest', script, ctx.account_id, ctx.user_token,
            FAAS_BASE_URL, FAAS_HOST
        )
        assert deploy_resp.status_code == 200

        # Test large POST
        large_payload = 'a' * 50000
        resp = http_request(
            'POST',
            f'{FAAS_BASE_URL}/',
            headers={'Host': f'largetest.{FAAS_HOST}'},
            data=large_payload
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data['received'] == 50000

        # Test large GET response
        resp = http_request('GET', f'{FAAS_BASE_URL}/',
                           headers={'Host': f'largetest.{FAAS_HOST}'})
        assert resp.status_code == 200
        assert len(resp.text) == 100000

        print("✓ Function handles large payloads")

    def test_function_with_query_params(ctx):
        """Function parsing query parameters"""
        script = """
        export default {
            async fetch(request) {
                const url = new URL(request.url);
                const params = {};
                for (const [key, value] of url.searchParams) {
                    params[key] = value;
                }
                return Response.json(params);
            }
        }
        """

        _, deploy_resp, _ = create_and_deploy_function(
            'querytest', script, ctx.account_id, ctx.user_token,
            FAAS_BASE_URL, FAAS_HOST
        )
        assert deploy_resp.status_code == 200

        # Test with multiple query params
        resp = http_request(
            'GET',
            f'{FAAS_BASE_URL}/?foo=bar&num=123&flag=true',
            headers={'Host': f'querytest.{FAAS_HOST}'}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data['foo'] == 'bar'
        assert data['num'] == '123'
        assert data['flag'] == 'true'

        print("✓ Function parses query parameters correctly")

    def test_function_error_handling(ctx):
        """Function with error handling"""
        script = """
        export default {
            async fetch(request) {
                try {
                    const url = new URL(request.url);
                    if (url.searchParams.get('throw') === 'true') {
                        throw new Error('Intentional error');
                    }
                    return Response.json({success: true});
                } catch (error) {
                    return Response.json({
                        error: error.message
                    }, {status: 500});
                }
            }
        }
        """

        _, deploy_resp, _ = create_and_deploy_function(
            'errortest', script, ctx.account_id, ctx.user_token,
            FAAS_BASE_URL, FAAS_HOST
        )
        assert deploy_resp.status_code == 200

        # Normal request
        resp = http_request('GET', f'{FAAS_BASE_URL}/',
                           headers={'Host': f'errortest.{FAAS_HOST}'})
        assert resp.status_code == 200
        assert resp.json()['success'] == True

        # Request that triggers error
        resp = http_request('GET', f'{FAAS_BASE_URL}/?throw=true',
                           headers={'Host': f'errortest.{FAAS_HOST}'})
        assert resp.status_code == 500
        assert 'error' in resp.json()

        print("✓ Function error handling works")

    def test_function_with_cookies(ctx):
        """Function handling cookies"""
        script = """
        export default {
            async fetch(request) {
                const url = new URL(request.url);
                if (url.searchParams.get('set') === 'true') {
                    return new Response('Cookie set', {
                        headers: {
                            'Set-Cookie': 'session=abc123; Path=/; HttpOnly'
                        }
                    });
                }
                const cookies = request.headers.get('cookie') || 'none';
                return new Response(cookies);
            }
        }
        """

        _, deploy_resp, _ = create_and_deploy_function(
            'cookietest', script, ctx.account_id, ctx.user_token,
            FAAS_BASE_URL, FAAS_HOST
        )
        assert deploy_resp.status_code == 200

        # Set cookie
        resp = http_request('GET', f'{FAAS_BASE_URL}/?set=true',
                           headers={'Host': f'cookietest.{FAAS_HOST}'})
        assert resp.status_code == 200
        assert 'Set-Cookie' in resp.headers or 'set-cookie' in resp.headers

        # Send cookie
        resp = http_request('GET', f'{FAAS_BASE_URL}/',
                           headers={
                               'Host': f'cookietest.{FAAS_HOST}',
                               'Cookie': 'session=abc123'
                           })
        assert resp.status_code == 200
        assert 'session=abc123' in resp.text

        print("✓ Function handles cookies correctly")

    suite.add_test(test_function_with_env_vars)
    suite.add_test(test_multiple_modules)
    suite.add_test(test_invalid_metadata)
    suite.add_test(test_function_with_fetch_request)
    suite.add_test(test_function_response_types)
    suite.add_test(test_function_with_large_payload)
    suite.add_test(test_function_with_query_params)
    suite.add_test(test_function_error_handling)
    suite.add_test(test_function_with_cookies)

    return suite
