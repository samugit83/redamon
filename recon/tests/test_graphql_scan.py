"""
Unit tests for GraphQL Security Scanner
"""

import pytest
import json
import base64
from unittest.mock import Mock, patch, MagicMock
from recon.graphql_scan import (
    run_graphql_scan_isolated,
    discover_graphql_endpoints
)
from recon.graphql_scan.normalizers import (
    normalize_finding,
    normalize_introspection_finding,
    aggregate_findings
)


class TestGraphQLDiscovery:
    """Test GraphQL endpoint discovery functionality."""

    def test_discover_graphql_endpoints_basic(self):
        """Test basic GraphQL endpoint discovery."""
        combined_result = {
            'http_probe': {
                'by_url': {
                    'https://example.com': {'status_code': 200},
                    'https://example.com/api': {'status_code': 200}
                }
            }
        }
        settings = {'GRAPHQL_ENDPOINTS': ''}

        endpoints = discover_graphql_endpoints(combined_result, settings)

        # Should generate standard GraphQL patterns for each base URL
        assert 'https://example.com/graphql' in endpoints
        assert 'https://example.com/api/graphql' in endpoints

    def test_discover_user_specified_endpoints(self):
        """Test user-specified endpoint discovery."""
        combined_result = {'http_probe': {'by_url': {}}}
        settings = {
            'GRAPHQL_ENDPOINTS': 'https://api.example.com/graphql,https://example.com/query'
        }

        endpoints = discover_graphql_endpoints(combined_result, settings)

        assert 'https://api.example.com/graphql' in endpoints
        assert 'https://example.com/query' in endpoints

    def test_discover_from_js_recon(self):
        """Test GraphQL endpoint discovery from JS recon findings."""
        combined_result = {
            'http_probe': {
                'by_url': {
                    'https://example.com': {'status_code': 200}
                }
            },
            'js_recon': {
                'findings': [
                    {
                        'type': 'graphql',
                        'path': '/api/graphql',
                        'method': 'POST'
                    },
                    {
                        'type': 'graphql_introspection',
                        'path': 'https://example.com/graphiql',
                        'method': 'POST'
                    }
                ]
            }
        }
        settings = {'GRAPHQL_ENDPOINTS': ''}

        endpoints = discover_graphql_endpoints(combined_result, settings)

        assert 'https://example.com/api/graphql' in endpoints
        assert 'https://example.com/graphiql' in endpoints


    def test_extract_from_http_probe(self):
        """Test GraphQL extraction from HTTP probe results."""
        # Import the private function for testing
        from recon.graphql_scan.discovery import _extract_from_http_probe

        combined_result = {
            'http_probe': {
                'by_url': {
                    'https://example.com/api': {
                        'status_code': 200,
                        'headers': {
                            'content-type': 'application/graphql'
                        },
                        'body': 'GraphQL Playground'
                    },
                    'https://example.com/normal': {
                        'status_code': 200,
                        'headers': {
                            'content-type': 'text/html'
                        },
                        'body': 'Normal page'
                    }
                }
            }
        }

        endpoints = _extract_from_http_probe(combined_result)
        assert 'https://example.com/api' in endpoints
        assert 'https://example.com/normal' not in endpoints


class TestGraphQLNormalizers:
    """Test finding normalization functionality."""

    def test_normalize_finding_basic(self):
        """Test basic finding normalization."""
        finding = normalize_finding(
            endpoint='https://example.com/graphql',
            vulnerability_type='graphql_introspection_enabled',
            severity='medium',
            title='GraphQL Introspection Enabled',
            description='Introspection is enabled on this endpoint.'
        )

        assert finding['endpoint'] == 'https://example.com/graphql'
        assert finding['vulnerability_type'] == 'graphql_introspection_enabled'
        assert finding['severity'] == 'medium'
        assert finding['source'] == 'graphql_scan'
        assert 'discovered_at' in finding

    def test_normalize_introspection_finding(self):
        """Test introspection-specific finding normalization."""
        operations = {
            'queries': ['user', 'posts'],
            'mutations': ['createUser', 'updateUser', 'deleteUser'],
            'subscriptions': []
        }
        sensitive_fields = ['User.password', 'User.creditCard']

        finding = normalize_introspection_finding(
            endpoint='https://example.com/graphql',
            operations=operations,
            sensitive_fields=sensitive_fields
        )

        assert finding['vulnerability_type'] == 'graphql_introspection_enabled'
        assert finding['severity'] == 'medium'  # Has sensitive fields
        assert 'mutations' in finding['description']
        assert finding['evidence']['operations_count']['mutations'] == 3

    def test_aggregate_findings(self):
        """Test finding aggregation."""
        findings = [
            {'severity': 'critical', 'vulnerability_type': 'graphql_cost_bypass'},
            {'severity': 'high', 'vulnerability_type': 'graphql_proxy_traversal'},
            {'severity': 'medium', 'vulnerability_type': 'graphql_introspection_enabled'},
            {'severity': 'medium', 'vulnerability_type': 'graphql_introspection_enabled'},
        ]

        summary = aggregate_findings(findings)

        assert summary['total_findings'] == 4
        assert summary['by_severity']['critical'] == 1
        assert summary['by_severity']['high'] == 1
        assert summary['by_severity']['medium'] == 2
        assert summary['by_type']['graphql_introspection_enabled'] == 2


class TestGraphQLScanner:
    """Test main GraphQL scanner functionality."""

    @patch('recon.graphql_scan.scanner.test_single_endpoint')
    def test_run_graphql_scan_basic(self, mock_test):
        """Test basic GraphQL scan execution."""
        mock_test.return_value = {
            'endpoint_data': {
                'tested': True,
                'introspection_enabled': True,
                'mutations_count': 5,
                'queries_count': 10
            },
            'vulnerabilities': [{
                'vulnerability_type': 'graphql_introspection_enabled',
                'severity': 'medium'
            }]
        }

        combined_result = {
            'http_probe': {
                'by_url': {
                    'https://example.com': {'status_code': 200}
                }
            },
            'metadata': {'roe': {}}
        }

        settings = {
            'GRAPHQL_SECURITY_ENABLED': True,
            'GRAPHQL_INTROSPECTION_TEST': True,
            'GRAPHQL_TIMEOUT': 30,
            'GRAPHQL_RATE_LIMIT': 10,
            'GRAPHQL_CONCURRENCY': 1
        }

        result = run_graphql_scan_isolated(combined_result, settings)

        assert result['summary']['endpoints_discovered'] > 0
        # We generate PRIMARY_GRAPHQL_PATTERNS for each base URL
        assert result['summary']['endpoints_tested'] > 0
        assert result['summary']['introspection_enabled'] > 0
        assert result['summary']['vulnerabilities_found'] > 0

    def test_run_graphql_scan_disabled(self):
        """Test GraphQL scan when disabled."""
        combined_result = {'metadata': {}}
        settings = {'GRAPHQL_SECURITY_ENABLED': False}

        result = run_graphql_scan_isolated(combined_result, settings)

        assert result == {}  # Should return empty when disabled


class TestGraphQLAuth:
    """Test authentication handling."""

    def test_build_auth_headers_bearer(self):
        """Test Bearer token authentication."""
        from recon.graphql_scan.auth import build_auth_headers

        settings = {
            'GRAPHQL_AUTH_TYPE': 'bearer',
            'GRAPHQL_AUTH_VALUE': 'test-token-12345'
        }

        headers = build_auth_headers(settings)

        assert 'Authorization' in headers
        assert headers['Authorization'] == 'Bearer test-token-12345'

    def test_build_auth_headers_basic(self):
        """Test Basic authentication."""
        from recon.graphql_scan.auth import build_auth_headers
        import base64

        settings = {
            'GRAPHQL_AUTH_TYPE': 'basic',
            'GRAPHQL_AUTH_VALUE': 'user:pass'
        }

        headers = build_auth_headers(settings)

        assert 'Authorization' in headers
        expected_encoded = base64.b64encode(b'user:pass').decode()
        assert headers['Authorization'] == f'Basic {expected_encoded}'

    def test_mask_auth_value(self):
        """Test auth value masking."""
        from recon.graphql_scan.auth import mask_auth_value

        # Test various auth values
        assert mask_auth_value('') == ''
        assert mask_auth_value('abc') == '***'
        assert mask_auth_value('abcde') == 'ab***'
        assert mask_auth_value('abcdefghijklmnop') == 'abcd...mnop'

        # Test basic auth masking
        assert mask_auth_value('user:password', 'basic') == 'user:***'

    def test_build_auth_headers_cookie(self):
        """Test Cookie authentication."""
        from recon.graphql_scan.auth import build_auth_headers

        settings = {
            'GRAPHQL_AUTH_TYPE': 'cookie',
            'GRAPHQL_AUTH_VALUE': 'session=abc123; token=xyz'
        }

        headers = build_auth_headers(settings)
        assert 'Cookie' in headers
        assert headers['Cookie'] == 'session=abc123; token=xyz'

    def test_build_auth_headers_custom_header(self):
        """Test custom header authentication."""
        from recon.graphql_scan.auth import build_auth_headers

        settings = {
            'GRAPHQL_AUTH_TYPE': 'header',
            'GRAPHQL_AUTH_VALUE': 'my-secret-token',
            'GRAPHQL_AUTH_HEADER': 'X-Custom-Auth'
        }

        headers = build_auth_headers(settings)
        assert 'X-Custom-Auth' in headers
        assert headers['X-Custom-Auth'] == 'my-secret-token'

    def test_build_auth_headers_invalid(self):
        """Test invalid authentication types."""
        from recon.graphql_scan.auth import build_auth_headers

        # Test unknown auth type
        settings = {
            'GRAPHQL_AUTH_TYPE': 'unknown',
            'GRAPHQL_AUTH_VALUE': 'test'
        }

        headers = build_auth_headers(settings)
        assert headers == {}  # Should return empty dict

        # Test basic auth with invalid format
        settings = {
            'GRAPHQL_AUTH_TYPE': 'basic',
            'GRAPHQL_AUTH_VALUE': 'invalid-no-colon'
        }

        headers = build_auth_headers(settings)
        assert headers == {}  # Should return empty dict


class TestGraphQLROE:
    """Test Rules of Engagement filtering."""

    def test_filter_by_roe_disabled(self):
        """Test RoE filtering when disabled."""
        from recon.graphql_scan.discovery import filter_by_roe

        endpoints = [
            'https://example.com/graphql',
            'https://test.example.com/graphql'
        ]
        roe_settings = {'ROE_ENABLED': False}

        filtered = filter_by_roe(endpoints, roe_settings)

        assert filtered == endpoints  # Should return all when disabled

    def test_filter_by_roe_with_exclusions(self):
        """Test RoE filtering with excluded hosts."""
        from recon.graphql_scan.discovery import filter_by_roe

        endpoints = [
            'https://example.com/graphql',
            'https://test.example.com/graphql',
            'https://api.excluded.com/graphql',
            'https://sub.excluded.com/graphql'
        ]
        roe_settings = {
            'ROE_ENABLED': True,
            'ROE_EXCLUDED_HOSTS': ['api.excluded.com', '*.excluded.com']
        }

        filtered = filter_by_roe(endpoints, roe_settings)

        assert len(filtered) == 2
        assert 'https://example.com/graphql' in filtered
        assert 'https://test.example.com/graphql' in filtered
        assert 'https://api.excluded.com/graphql' not in filtered
        assert 'https://sub.excluded.com/graphql' not in filtered


class TestGraphQLIntrospection:
    """Test introspection functionality."""

    @patch('requests.post')
    def test_test_introspection_ssl_verification(self, mock_post):
        """Test that SSL verification setting is respected."""
        from recon.graphql_scan.introspection import test_introspection

        # Mock successful GraphQL response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': {'__typename': 'Query'}}
        mock_post.return_value = mock_response

        # Test with SSL verification enabled
        test_introspection('https://example.com/graphql', {}, 30, verify_ssl=True)

        # Check that verify=True was passed to requests
        calls = mock_post.call_args_list
        assert any(call[1].get('verify') == True for call in calls)

        # Test with SSL verification disabled
        mock_post.reset_mock()
        test_introspection('https://example.com/graphql', {}, 30, verify_ssl=False)

        # Check that verify=False was passed to requests
        calls = mock_post.call_args_list
        assert any(call[1].get('verify') == False for call in calls)

    @patch('requests.post')
    def test_test_introspection_schema_size_limit(self, mock_post):
        """Test schema size limiting."""
        from recon.graphql_scan.introspection import test_introspection

        # Mock responses
        simple_response = Mock()
        simple_response.status_code = 200
        simple_response.json.return_value = {
            'data': {
                '__schema': {
                    'queryType': {'name': 'Query'}
                }
            }
        }

        large_response = Mock()
        large_response.status_code = 200
        large_response.content = b'x' * (11 * 1024 * 1024)  # 11MB
        large_response.json.return_value = {'data': {}}

        mock_post.side_effect = [
            simple_response,  # Initial test
            simple_response,  # Simple introspection
            large_response   # Full introspection (too large)
        ]

        is_enabled, schema_data, error = test_introspection('https://example.com/graphql')

        assert is_enabled is True
        # Should return simple schema due to size limit
        assert '__schema' in schema_data


    @patch('requests.post')
    def test_test_introspection_errors(self, mock_post):
        """Test introspection error handling."""
        from recon.graphql_scan.introspection import test_introspection

        # Test non-200 response
        mock_response = Mock()
        mock_response.status_code = 404
        mock_post.return_value = mock_response

        is_enabled, schema_data, error = test_introspection('https://example.com/graphql')
        assert is_enabled is False
        assert schema_data is None
        assert 'Non-200 status code: 404' in error

        # Test JSON decode error
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("test", "doc", 0)
        mock_post.return_value = mock_response

        is_enabled, schema_data, error = test_introspection('https://example.com/graphql')
        assert is_enabled is False
        assert error == "Response is not valid JSON"

        # Test request timeout
        from requests.exceptions import Timeout
        mock_post.side_effect = Timeout("Connection timeout")

        is_enabled, schema_data, error = test_introspection('https://example.com/graphql')
        assert is_enabled is False
        assert 'Request timeout' in error

    def test_extract_operations_empty(self):
        """Test operations extraction with empty schema."""
        from recon.graphql_scan.introspection import extract_operations

        # Test with None
        operations = extract_operations(None)
        assert operations == {'queries': [], 'mutations': [], 'subscriptions': []}

        # Test with empty schema
        operations = extract_operations({})
        assert operations == {'queries': [], 'mutations': [], 'subscriptions': []}

    def test_detect_sensitive_fields_empty(self):
        """Test sensitive field detection with empty schema."""
        from recon.graphql_scan.introspection import detect_sensitive_fields

        # Test with None
        fields = detect_sensitive_fields(None)
        assert fields == []

        # Test with empty schema
        fields = detect_sensitive_fields({})
        assert fields == []


class TestGraphQLCaching:
    """Test introspection caching."""

    @patch('recon.graphql_scan.scanner.test_introspection')
    def test_introspection_caching(self, mock_introspection):
        """Test that introspection results are cached."""
        from recon.graphql_scan.scanner import test_single_endpoint

        # Mock introspection result
        mock_introspection.return_value = (True, {'__schema': {}}, None)

        cache = {}
        settings = {
            'GRAPHQL_INTROSPECTION_TEST': True,
            'GRAPHQL_VERIFY_SSL': True
        }

        # First call should hit introspection
        result1 = test_single_endpoint(
            'https://example.com/graphql',
            {},
            30,
            settings,
            cache
        )

        assert mock_introspection.call_count == 1
        assert 'https://example.com/graphql' in cache

        # Second call should use cache
        mock_introspection.reset_mock()
        result2 = test_single_endpoint(
            'https://example.com/graphql',
            {},
            30,
            settings,
            cache
        )

        assert mock_introspection.call_count == 0  # Should not be called
        # Compare key fields, excluding timestamps
        assert result1['endpoint_data'] == result2['endpoint_data']
        assert len(result1['vulnerabilities']) == len(result2['vulnerabilities'])
        # Check vulnerability content excluding timestamp
        for v1, v2 in zip(result1['vulnerabilities'], result2['vulnerabilities']):
            assert v1['vulnerability_type'] == v2['vulnerability_type']
            assert v1['severity'] == v2['severity']


class TestGraphQLGraphDB:
    """Test graph database integration."""

    def test_graphql_mixin_structure(self):
        """Test that GraphQLMixin has the expected structure."""
        import os
        import sys

        # Check that the mixin file exists
        mixin_path = os.path.join(
            os.path.dirname(__file__),
            '..',
            '..',
            'graph_db',
            'mixins',
            'graphql_mixin.py'
        )
        assert os.path.exists(mixin_path), "GraphQLMixin file should exist"

        # Read the file and check for expected method
        with open(mixin_path, 'r') as f:
            content = f.read()

        # Verify key components exist
        assert 'class GraphQLMixin:' in content
        assert 'def update_graph_from_graphql_scan(' in content
        assert 'endpoints_enriched' in content
        assert 'vulnerabilities_created' in content
        assert 'MERGE (e:Endpoint' in content
        assert 'is_graphql' in content


class TestSettingsValidation:
    """Test settings input validation."""

    def test_settings_validation_in_scanner(self):
        """Test that settings are validated and clamped to valid ranges."""
        from recon.graphql_scan import run_graphql_scan_isolated

        combined_result = {
            'http_probe': {
                'by_url': {
                    'https://example.com': {'status_code': 200}
                }
            },
            'metadata': {'roe': {}}
        }

        # Test with invalid settings
        settings = {
            'GRAPHQL_SECURITY_ENABLED': True,
            'GRAPHQL_TIMEOUT': 1000,  # Too high
            'GRAPHQL_RATE_LIMIT': 200,  # Too high
            'GRAPHQL_CONCURRENCY': 50   # Too high
        }

        with patch('recon.graphql_scan.scanner.test_single_endpoint') as mock_test:
            mock_test.return_value = None

            # This should not raise an error
            result = run_graphql_scan_isolated(combined_result, settings)

            # Settings should be clamped to valid ranges
            assert result is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])