"""Version management tests."""

import json
from framework import TestSuite
from helpers import create_function, deploy_function, http_request
from config import FAAS_BASE_URL, FAAS_HOST


def create_version_suite():
    """Create version management test suite."""
    suite = TestSuite("Version Management Tests")

    def test_function_update_and_versioning(ctx):
        """Function update creates new version"""
        func_name = "versiontest"

        # Create version 1
        script_v1 = "export default { async fetch() { return new Response('V1'); } }"
        _, v1_id = create_function(func_name, script_v1, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST)
        assert v1_id is not None

        # Create version 2
        script_v2 = "export default { async fetch() { return new Response('V2'); } }"
        _, v2_id = create_function(func_name, script_v2, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST)
        assert v2_id is not None
        assert v1_id != v2_id

        # List versions
        response = http_request(
            'GET',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/{func_name}/versions',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}',
            }
        )
        assert response.status_code == 200
        versions = response.json()['result']
        version_ids = [v['id'] for v in versions]
        assert v1_id in version_ids
        assert v2_id in version_ids

        print("✓ Function update creates new versions")

    def test_alias_operations(ctx):
        """Alias operations"""
        func_name = "aliastest"

        # Create function
        script = "export default { async fetch() { return new Response('Test'); } }"
        _, version_id = create_function(func_name, script, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST)

        # Create alias
        response = http_request(
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/{func_name}/aliases/prod',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}',
                'Content-Type': 'application/json'
            },
            data=json.dumps({'version_id': version_id})
        )
        assert response.status_code == 200

        # List aliases
        response = http_request(
            'GET',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/{func_name}/aliases',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}',
            }
        )
        assert response.status_code == 200
        aliases = response.json()['result']
        alias_names = [a['name'] for a in aliases]
        assert 'prod' in alias_names

        print("✓ Alias operations work correctly")

    def test_deployment_strategies(ctx):
        """Deployment strategies"""
        func_name = "deploytest"

        # Create function
        script = "export default { async fetch() { return new Response('Test'); } }"
        _, version_id = create_function(func_name, script, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST)

        # Valid deployment (100%)
        response = deploy_function(func_name, version_id, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST, 100)
        assert response.status_code == 200

        # Invalid deployment (not 100%)
        response = http_request(
            'POST',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/{func_name}/deployments',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}',
                'Content-Type': 'application/json'
            },
            data=json.dumps({
                'strategy': 'percentage',
                'versions': [{'version_id': version_id, 'percentage': 50}]
            })
        )
        assert response.status_code == 400

        print("✓ Deployment strategies validated correctly")

    suite.add_test(test_function_update_and_versioning)
    suite.add_test(test_alias_operations)
    suite.add_test(test_deployment_strategies)

    return suite
