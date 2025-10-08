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

    def test_alias_routing(ctx):
        """Alias routing to correct version"""
        func_name = "routetest"

        # Create two versions
        script_v1 = "export default { async fetch() { return new Response('Version 1'); } }"
        _, v1_id = create_function(func_name, script_v1, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST)

        script_v2 = "export default { async fetch() { return new Response('Version 2'); } }"
        _, v2_id = create_function(func_name, script_v2, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST)

        # Create alias pointing to v1
        response = http_request(
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/{func_name}/aliases/stable',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}',
                'Content-Type': 'application/json'
            },
            data=json.dumps({'version_id': v1_id})
        )
        assert response.status_code == 200

        # Deploy v2 to main
        deploy_resp = deploy_function(func_name, v2_id, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST)
        assert deploy_resp.status_code == 200

        import time
        time.sleep(0.1)

        # Test main route (should get v2)
        resp = http_request('GET', f'{FAAS_BASE_URL}/',
                           headers={'Host': f'{func_name}.{FAAS_HOST}'})
        assert resp.status_code == 200
        assert 'Version 2' in resp.text

        # Test alias route (should get v1)
        resp = http_request('GET', f'{FAAS_BASE_URL}/',
                           headers={'Host': f'stable.{func_name}.{FAAS_HOST}'})
        assert resp.status_code == 200
        assert 'Version 1' in resp.text

        print("✓ Alias routing works correctly")

    def test_alias_update(ctx):
        """Test updating an alias to point to different version"""
        func_name = "updatealias"

        # Create two versions
        script_v1 = "export default { async fetch() { return Response.json({version: 1}); } }"
        _, v1_id = create_function(func_name, script_v1, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST)

        script_v2 = "export default { async fetch() { return Response.json({version: 2}); } }"
        _, v2_id = create_function(func_name, script_v2, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST)

        # Create alias pointing to v1
        response = http_request(
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/{func_name}/aliases/current',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}',
                'Content-Type': 'application/json'
            },
            data=json.dumps({'version_id': v1_id})
        )
        assert response.status_code == 200

        # Deploy v1
        deploy_function(func_name, v1_id, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST)

        import time
        time.sleep(0.1)

        # Verify v1 response
        resp = http_request('GET', f'{FAAS_BASE_URL}/',
                           headers={'Host': f'current.{func_name}.{FAAS_HOST}'})
        assert resp.status_code == 200
        assert resp.json()['version'] == 1

        # Update alias to v2
        response = http_request(
            'PUT',
            f'{FAAS_BASE_URL}/accounts/{ctx.account_id}/workers/scripts/{func_name}/aliases/current',
            headers={
                'Host': FAAS_HOST,
                'Authorization': f'Bearer {ctx.user_token}',
                'Content-Type': 'application/json'
            },
            data=json.dumps({'version_id': v2_id})
        )
        assert response.status_code == 200

        # Deploy v2
        deploy_function(func_name, v2_id, ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST)
        time.sleep(0.1)

        # Verify v2 response
        resp = http_request('GET', f'{FAAS_BASE_URL}/',
                           headers={'Host': f'current.{func_name}.{FAAS_HOST}'})
        assert resp.status_code == 200
        assert resp.json()['version'] == 2

        print("✓ Alias update works correctly")

    def test_nonexistent_version_deploy(ctx):
        """Test deploying nonexistent version"""
        func_name = "nosuchversion"

        # Try to deploy nonexistent version
        response = deploy_function(
            func_name, 'nonexistent-version-id',
            ctx.account_id, ctx.user_token, FAAS_BASE_URL, FAAS_HOST
        )
        # Should fail with 404 or 400
        assert response.status_code in [400, 404]

        print("✓ Nonexistent version deployment rejected")

    suite.add_test(test_function_update_and_versioning)
    suite.add_test(test_alias_operations)
    suite.add_test(test_deployment_strategies)
    suite.add_test(test_alias_routing)
    suite.add_test(test_alias_update)
    suite.add_test(test_nonexistent_version_deploy)

    return suite
