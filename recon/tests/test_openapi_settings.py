from unittest.mock import Mock, patch

from recon.project_settings import DEFAULT_SETTINGS, fetch_project_settings


EXPECTED_DEFAULTS = {
    "OPENAPI_ENABLED": True,
    "OPENAPI_AUTO_DISCOVER": True,
    "OPENAPI_SOURCES": [],
    "OPENAPI_DISCOVERY_HEADERS": [],
    "OPENAPI_TIMEOUT": 10,
    "OPENAPI_MAX_DOCUMENTS": 50,
}


def _fetch(project):
    project_response = Mock()
    project_response.json.return_value = project
    project_response.raise_for_status.return_value = None
    user_response = Mock()
    user_response.json.return_value = {}
    user_response.raise_for_status.return_value = None
    with patch("requests.get", side_effect=[project_response, user_response]):
        return fetch_project_settings("project-test", "http://webapp.test")


def test_openapi_defaults_match_the_ingestion_contract():
    assert {key: DEFAULT_SETTINGS[key] for key in EXPECTED_DEFAULTS} == EXPECTED_DEFAULTS


def test_openapi_settings_round_trip_from_project_api():
    sources = [{
        "id": "source-primary",
        "url": "https://docs.example.test/openapi.json",
        "headers": ["Authorization: Bearer test-token"],
        "serverOverride": "https://api.example.test/v2",
        "enabled": False,
    }]
    discovery_headers = [{
        "origin": "https://docs.example.test",
        "headers": ["X-API-Key: test-key"],
    }]
    result = _fetch({
        "openapiEnabled": False,
        "openapiAutoDiscover": False,
        "openapiSources": sources,
        "openapiDiscoveryHeaders": discovery_headers,
        "openapiTimeout": 17,
        "openapiMaxDocuments": 23,
    })

    assert result["OPENAPI_ENABLED"] is False
    assert result["OPENAPI_AUTO_DISCOVER"] is False
    assert result["OPENAPI_SOURCES"] == sources
    assert result["OPENAPI_DISCOVERY_HEADERS"] == discovery_headers
    assert result["OPENAPI_TIMEOUT"] == 17
    assert result["OPENAPI_MAX_DOCUMENTS"] == 23


def test_openapi_settings_fall_back_for_existing_projects():
    result = _fetch({})
    for key, value in EXPECTED_DEFAULTS.items():
        assert result[key] == value


def test_project_discovery_paths_preserve_custom_and_empty_values():
    assert _fetch({'openapiDiscoveryPaths': ['/custom/spec']})['OPENAPI_DISCOVERY_PATHS'] == ['/custom/spec']
    assert _fetch({'openapiDiscoveryPaths': []})['OPENAPI_DISCOVERY_PATHS'] == []