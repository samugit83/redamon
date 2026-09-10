"""Partial OpenAPI ingestion uses the same scope and parser as full recon."""
import os


def run_openapi_partial(config: dict) -> None:
    from graph_db import Neo4jClient
    from recon.project_settings import get_settings
    from recon.main_recon_modules.openapi_recon import run_openapi_recon
    from recon.partial_recon_modules.helpers import _should_include_root_domain
    from recon.partial_recon_modules.graph_builders import _build_http_probe_data_from_graph

    settings = dict(get_settings())
    settings['OPENAPI_ENABLED'] = True
    user_id = os.environ.get('USER_ID') or config.get('user_id', '')
    project_id = os.environ.get('PROJECT_ID') or config.get('project_id', '')
    if not user_id or not project_id:
        raise ValueError('OpenAPI partial recon requires a user and project')
    # Scope comes from stored project settings, never from user-entered URLs.
    domain = settings.get('TARGET_DOMAIN', '')
    if config.get('include_graph_targets', True):
        data = _build_http_probe_data_from_graph(domain, user_id, project_id,
                                                include_root_domain=_should_include_root_domain(settings))
    else:
        data = {'domain': domain, 'http_probe': {'by_url': {}}}
    for url in (config.get('user_targets') or {}).get('urls', []):
        data.setdefault('http_probe', {}).setdefault('by_url', {})[url] = {}
    run_openapi_recon(data, settings)
    if settings.get('UPDATE_GRAPH_DB', True):
        with Neo4jClient() as client:
            stats = client.update_graph_from_openapi(data, user_id, project_id)
            if stats.get('errors'):
                raise RuntimeError('OpenAPI graph ingestion incomplete')
    print(f"[+][OpenAPI] Partial recon complete: {len(data['openapi']['operations'])} declarations")
