"""Deployment helper utilities."""

import json
import time
from .http_client import http_request


def create_function(
    func_name,
    script,
    account_id,
    token,
    base_url="http://localhost:8080",
    host="func.local",
    metadata=None
):
    """
    Create a function version.

    Args:
        func_name: Name of the function
        script: JavaScript code
        account_id: Account ID
        token: JWT token
        base_url: Base URL of the FaaS service
        host: Host header value
        metadata: Optional metadata dict (will use defaults if not provided)

    Returns:
        Tuple of (response, version_id)
    """
    if metadata is None:
        metadata = {
            'main_module': 'index.js',
            'compatibility_date': '2025-01-01'
        }

    # Use the POST /versions endpoint to create a new version
    response = http_request(
        'POST',
        f'{base_url}/accounts/{account_id}/workers/scripts/{func_name}/versions',
        headers={
            'Host': host,
            'Authorization': f'Bearer {token}',
        },
        files={
            'metadata': (None, json.dumps(metadata)),
            'index.js': ('index.js', script)
        }
    )

    version_id = None
    if response.status_code == 200:
        result = response.json().get('result')
        if result:
            version_id = result.get('id')

    return response, version_id


def deploy_function(
    func_name,
    version_id,
    account_id,
    token,
    base_url="http://localhost:8080",
    host="func.local",
    percentage=100
):
    """
    Deploy a function version.

    Args:
        func_name: Name of the function
        version_id: Version ID to deploy
        account_id: Account ID
        token: JWT token
        base_url: Base URL of the FaaS service
        host: Host header value
        percentage: Deployment percentage (default 100)

    Returns:
        HTTP response
    """
    response = http_request(
        'POST',
        f'{base_url}/accounts/{account_id}/workers/scripts/{func_name}/deployments',
        headers={
            'Host': host,
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        },
        data=json.dumps({
            'strategy': 'percentage',
            'versions': [{'version_id': version_id, 'percentage': percentage}]
        })
    )

    return response


def create_and_deploy_function(
    func_name,
    script,
    account_id,
    token,
    base_url="http://localhost:8080",
    host="func.local",
    metadata=None,
    wait_time=0.1
):
    """
    Create and deploy a function in one call.

    Args:
        func_name: Name of the function
        script: JavaScript code
        account_id: Account ID
        token: JWT token
        base_url: Base URL of the FaaS service
        host: Host header value
        metadata: Optional metadata dict
        wait_time: Time to wait after deployment (seconds)

    Returns:
        Tuple of (create_response, deploy_response, version_id)
    """
    create_resp, version_id = create_function(
        func_name, script, account_id, token, base_url, host, metadata
    )

    if create_resp.status_code != 200:
        return create_resp, None, version_id

    deploy_resp = deploy_function(
        func_name, version_id, account_id, token, base_url, host
    )

    if wait_time > 0:
        time.sleep(wait_time)

    return create_resp, deploy_resp, version_id
