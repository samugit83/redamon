"""Partial OpenAPI ingestion uses the same scope and parser as full recon."""
import os


def run_openapi_partial(config: dict) -> dict | None:
    from graph_db import Neo4jClient
    from recon.main_recon_modules.openapi_recon import run_openapi_recon
    from recon.helpers.openapi.fetch import RequestPacer
    from recon.partial_recon_modules.helpers import (
        _should_include_root_domain, partial_settings, run_per_root, scope_roots,
    )
    from recon.partial_recon_modules.graph_builders import _build_http_probe_data_from_graph

    settings = dict(partial_settings(config))
    if settings.get('STEALTH_MODE', False):
        print('[*][OpenAPI] Partial recon skipped: stealth mode disables document fetching')
        return
    settings['OPENAPI_ENABLED'] = True
    user_id = os.environ.get('USER_ID') or config.get('user_id', '')
    project_id = os.environ.get('PROJECT_ID') or config.get('project_id', '')
    if not user_id or not project_id:
        raise ValueError('OpenAPI partial recon requires a user and project')
    target_settings = [settings]
    if settings.get('DOMAIN_BATCH_MODE'):
        target_settings = [{**settings, 'TARGET_DOMAIN': group['rootDomain'],
                            'SUBDOMAIN_LIST': list(group.get('prefixes') or [])}
                           for group in settings.get('DOMAIN_BATCH_GROUPS', [])]
        if not target_settings:
            raise ValueError('OpenAPI batch has no approved target groups')
    if config.get('_settings') is not None:
        allowed_roots = set(scope_roots(config))
        target_settings = [entry for entry in target_settings
                           if entry.get('TARGET_DOMAIN') in allowed_roots or settings.get('IP_MODE')]
    by_root = {entry.get('TARGET_DOMAIN', ''): entry for entry in target_settings}
    pacer = RequestPacer(settings.get('ROE_GLOBAL_MAX_RPS', 0))

    def run_root(domain):
        settings = by_root[domain]
        # Scope comes from stored project settings, never from user-entered URLs.
        domain = settings.get('TARGET_DOMAIN', '')
        if config.get('include_graph_targets', True):
            data = _build_http_probe_data_from_graph(domain, user_id, project_id,
                                                    include_root_domain=_should_include_root_domain(settings),
                                                    domain_groups=config.get('domain_groups'))
        else:
            data = {'domain': domain, 'http_probe': {'by_url': {}}}
        for url in (config.get('user_targets') or {}).get('urls', []):
            data.setdefault('http_probe', {}).setdefault('by_url', {})[url] = {}
        run_openapi_recon(data, settings, pacer=pacer)
        if settings.get('UPDATE_GRAPH_DB', True):
            with Neo4jClient() as client:
                stats = client.update_graph_from_openapi(data, user_id, project_id)
                if stats.get('errors'):
                    raise RuntimeError('OpenAPI graph ingestion incomplete')
        print(f"[+][OpenAPI] Partial recon complete: {len(data['openapi']['operations'])} declarations")

    return run_per_root(list(by_root), run_root, 'OpenAPI')
