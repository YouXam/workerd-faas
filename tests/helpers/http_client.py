"""HTTP client utilities using http.client."""

import http.client
import json
import uuid
from urllib.parse import urlparse


class HTTPResponse:
    """Simple HTTP response wrapper."""

    def __init__(self, status_code, text, headers):
        self.status_code = status_code
        self.text = text
        self.headers = headers

    def json(self):
        """Parse response as JSON."""
        return json.loads(self.text) if self.text else {}


def http_request(method, url, headers=None, data=None, files=None, allow_redirects=True):
    """
    Simple HTTP request using http.client.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        url: Full URL to request
        headers: Optional dict of headers
        data: Optional request body (string or dict)
        files: Optional dict for multipart/form-data
        allow_redirects: Whether to follow redirects

    Returns:
        HTTPResponse object
    """
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query

    conn = http.client.HTTPConnection(host, port, timeout=10)

    req_headers = headers or {}
    body = None

    if files:
        # Handle multipart/form-data
        boundary = f'----WebKitFormBoundary{uuid.uuid4().hex[:16]}'
        req_headers['Content-Type'] = f'multipart/form-data; boundary={boundary}'

        parts = []
        for key, value in files.items():
            parts.append(f'--{boundary}\r\n')
            if isinstance(value, tuple) and len(value) >= 2:
                filename, content = value[0], value[1]
                if filename:
                    parts.append(f'Content-Disposition: form-data; name="{key}"; filename="{filename}"\r\n')
                else:
                    parts.append(f'Content-Disposition: form-data; name="{key}"\r\n')
                parts.append('\r\n')
                parts.append(content)
                parts.append('\r\n')
        parts.append(f'--{boundary}--\r\n')
        body = ''.join(parts).encode('utf-8')
    elif data:
        if isinstance(data, dict):
            body = json.dumps(data).encode('utf-8')
            if 'Content-Type' not in req_headers:
                req_headers['Content-Type'] = 'application/json'
        elif isinstance(data, str):
            body = data.encode('utf-8')
        else:
            body = data

    if body:
        req_headers['Content-Length'] = str(len(body))

    try:
        conn.request(method, path, body, req_headers)
        response = conn.getresponse()
        response_data = response.read().decode('utf-8', errors='ignore')
        response_headers = dict(response.getheaders())

        return HTTPResponse(response.status, response_data, response_headers)
    except Exception as e:
        print(f"HTTP request failed: {e}")
        raise
    finally:
        conn.close()
