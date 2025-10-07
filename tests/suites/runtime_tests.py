"""Function runtime and execution tests."""

from framework import TestSuite
from helpers import create_and_deploy_function, http_request
from config import FAAS_BASE_URL, FAAS_HOST


def create_runtime_suite():
    """Create runtime test suite."""
    suite = TestSuite("Function Runtime Tests")

    def test_request_body_processing(ctx):
        """Request body processing"""
        script = """
        export default {
            async fetch(request) {
                const body = await request.text();
                return Response.json({
                    received: body,
                    length: body.length
                });
            }
        }
        """

        _, deploy_resp, _ = create_and_deploy_function(
            'bodytest', script, ctx.account_id, ctx.user_token,
            FAAS_BASE_URL, FAAS_HOST
        )
        assert deploy_resp.status_code == 200

        # Test with body
        test_data = "Hello World!"
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/',
            headers={'Host': f'bodytest.{FAAS_HOST}'},
            data=test_data
        )
        assert response.status_code == 200
        result = response.json()
        assert result['received'] == test_data
        assert result['length'] == len(test_data)

        print("✓ Request body processing works")

    def test_query_parameters(ctx):
        """Query parameter processing"""
        script = """
        export default {
            async fetch(request) {
                const url = new URL(request.url);
                const params = {};
                for (const [key, value] of url.searchParams.entries()) {
                    params[key] = value;
                }
                return Response.json({ params });
            }
        }
        """

        _, deploy_resp, _ = create_and_deploy_function(
            'querytest', script, ctx.account_id, ctx.user_token,
            FAAS_BASE_URL, FAAS_HOST
        )
        assert deploy_resp.status_code == 200

        # Test with query params
        response = http_request(
            'GET',
            f'{FAAS_BASE_URL}/search?q=test&page=1',
            headers={'Host': f'querytest.{FAAS_HOST}'}
        )
        assert response.status_code == 200
        result = response.json()
        assert result['params']['q'] == 'test'
        assert result['params']['page'] == '1'

        print("✓ Query parameters work correctly")

    def test_json_response(ctx):
        """JSON response"""
        script = """
        export default {
            async fetch(request) {
                return Response.json({
                    status: 'success',
                    data: { users: ['Alice', 'Bob'] }
                });
            }
        }
        """

        _, deploy_resp, _ = create_and_deploy_function(
            'jsontest', script, ctx.account_id, ctx.user_token,
            FAAS_BASE_URL, FAAS_HOST
        )
        assert deploy_resp.status_code == 200

        response = http_request('GET', f'{FAAS_BASE_URL}/', headers={'Host': f'jsontest.{FAAS_HOST}'})
        assert response.status_code == 200
        result = response.json()
        assert result['status'] == 'success'
        assert len(result['data']['users']) == 2

        print("✓ JSON responses work correctly")

    suite.add_test(test_request_body_processing)
    suite.add_test(test_query_parameters)
    suite.add_test(test_json_response)

    return suite
