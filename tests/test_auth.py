#!/usr/bin/env python3
"""
Tests for Granian authentication functionality.
"""

import base64
import pytest
from granian.auth import BasicAuth, HtpasswdAuth, extract_auth_header


class TestBasicAuth:
    """Test basic authentication functionality."""

    def test_basic_auth_validation(self):
        """Test basic authentication validation."""
        auth = BasicAuth('admin', 'secret', 'Test Realm')

        # Valid credentials
        valid_header = 'Basic ' + base64.b64encode(b'admin:secret').decode('utf-8')
        assert auth.validate_credentials(valid_header) is True

        # Invalid credentials
        invalid_header = 'Basic ' + base64.b64encode(b'admin:wrong').decode('utf-8')
        assert auth.validate_credentials(invalid_header) is False

        # No header
        assert auth.validate_credentials(None) is False

        # Invalid format
        assert auth.validate_credentials('Invalid') is False

        # Missing password
        invalid_header2 = 'Basic ' + base64.b64encode(b'admin').decode('utf-8')
        assert auth.validate_credentials(invalid_header2) is False

    def test_unauthorized_headers(self):
        """Test unauthorized response headers."""
        auth = BasicAuth('admin', 'secret', 'Test Realm')
        headers = auth.get_unauthorized_response_headers()

        assert 'WWW-Authenticate' in headers
        assert headers['WWW-Authenticate'] == 'Basic realm="Test Realm"'


class TestHtpasswdAuth:
    """Test htpasswd authentication functionality."""

    def test_htpasswd_plain_text(self, tmp_path):
        """Test htpasswd with plain text passwords."""
        htpasswd_file = tmp_path / '.htpasswd'
        htpasswd_file.write_text('admin:secret\nuser2:password2\n')

        auth = HtpasswdAuth(str(htpasswd_file), 'Test Realm')

        # Valid credentials
        valid_header = 'Basic ' + base64.b64encode(b'admin:secret').decode('utf-8')
        assert auth.validate_credentials(valid_header) is True

        # Invalid credentials
        invalid_header = 'Basic ' + base64.b64encode(b'admin:wrong').decode('utf-8')
        assert auth.validate_credentials(invalid_header) is False

        # Non-existent user
        invalid_header2 = 'Basic ' + base64.b64encode(b'nonexistent:secret').decode('utf-8')
        assert auth.validate_credentials(invalid_header2) is False

    def test_htpasswd_sha1(self, tmp_path):
        """Test htpasswd with SHA1 hashed passwords."""
        import hashlib

        htpasswd_file = tmp_path / '.htpasswd'
        password_hash = base64.b64encode(hashlib.sha1(b'secret').digest()).decode()
        htpasswd_file.write_text(f'admin:{{SHA}}{password_hash}\n')

        auth = HtpasswdAuth(str(htpasswd_file), 'Test Realm')

        # Valid credentials
        valid_header = 'Basic ' + base64.b64encode(b'admin:secret').decode('utf-8')
        assert auth.validate_credentials(valid_header) is True

        # Invalid credentials
        invalid_header = 'Basic ' + base64.b64encode(b'admin:wrong').decode('utf-8')
        assert auth.validate_credentials(invalid_header) is False


class TestAuthUtilities:
    """Test authentication utility functions."""

    def test_validate_basic_auth(self):
        """Test validate_basic_auth utility function."""
        auth = BasicAuth('admin', 'secret', 'Test Realm')

        # Valid credentials
        valid_header = 'Basic ' + base64.b64encode(b'admin:secret').decode('utf-8')
        assert auth.validate_credentials(valid_header) is True

        # Invalid credentials
        invalid_header = 'Basic ' + base64.b64encode(b'admin:wrong').decode('utf-8')
        assert auth.validate_credentials(invalid_header) is False

        # No header
        assert auth.validate_credentials(None) is False

    def test_extract_auth_header(self):
        """Test extract_auth_header utility function."""
        headers = {
            'authorization': 'Basic dGVzdA==',
            'Authorization': 'Bearer token',
            'HTTP_AUTHORIZATION': 'Basic dGVzdDI=',
        }

        # Should find the first matching header
        assert extract_auth_header(headers) == 'Basic dGVzdA=='

        # No auth header
        assert extract_auth_header({}) is None


if __name__ == '__main__':
    pytest.main([__file__])
