"""
RedAmon - Endpoint Organization Helpers
=======================================
Functions for organizing and structuring discovered endpoints.
"""

from typing import Dict, List
from urllib.parse import urlparse, parse_qs

from .classification import classify_endpoint, classify_parameter, infer_parameter_type
from .katana_helpers import fetch_forms_from_urls


def organize_endpoints(
    discovered_urls: List[str]
) -> Dict:
    """
    Organize discovered URLs into structured endpoint data.

    Args:
        discovered_urls: List of URLs discovered by Katana

    Returns:
        Structured endpoint data organized by base URL
    """
    # Track endpoints by base URL
    by_base_url = {}  # base_url -> {path -> endpoint_info}

    # Fetch forms directly from discovered URLs (since http_probe doesn't keep body)
    all_forms = fetch_forms_from_urls(discovered_urls, max_urls=100)

    # Process each discovered URL
    for url in discovered_urls:
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme or 'http'
            host = parsed.netloc
            path = parsed.path or '/'
            query_string = parsed.query

            base_url = f"{scheme}://{host}"

            # Initialize base URL entry
            if base_url not in by_base_url:
                by_base_url[base_url] = {}

            # Initialize endpoint entry
            if path not in by_base_url[base_url]:
                by_base_url[base_url][path] = {
                    'path': path,
                    'methods': ['GET'],
                    'parameters': {
                        'query': [],
                        'body': [],
                        'path': []
                    },
                    'sample_urls': [],
                    'urls_found': 0
                }

            endpoint = by_base_url[base_url][path]
            endpoint['urls_found'] += 1

            # Keep sample URLs (max 3)
            if len(endpoint['sample_urls']) < 3:
                endpoint['sample_urls'].append(url)

            # Parse query parameters
            if query_string:
                params = parse_qs(query_string, keep_blank_values=True)
                for param_name, param_values in params.items():
                    # Check if param already exists
                    existing_param = next(
                        (p for p in endpoint['parameters']['query'] if p['name'] == param_name),
                        None
                    )

                    if existing_param:
                        # Add new sample values
                        for val in param_values:
                            if val and val not in existing_param['sample_values']:
                                existing_param['sample_values'].append(val)
                                if len(existing_param['sample_values']) >= 5:
                                    break
                        # The type follows every value seen, not the first URL's.
                        existing_param['type'] = infer_parameter_type(
                            param_name, existing_param['sample_values'])
                    else:
                        # Create new parameter entry
                        sample_values = [v for v in param_values if v][:5]
                        param_info = {
                            'name': param_name,
                            'type': infer_parameter_type(param_name, sample_values),
                            'sample_values': sample_values,
                            'category': classify_parameter(param_name)
                        }
                        endpoint['parameters']['query'].append(param_info)

        except Exception as e:
            continue

    # Process forms fetched from HTML pages
    for form in all_forms:
        # Add form as endpoint
        action_url = form['action']
        parsed = urlparse(action_url)
        scheme = parsed.scheme or 'http'
        host = parsed.netloc
        path = parsed.path or '/'
        base_url = f"{scheme}://{host}"
        method = form['method']

        if base_url not in by_base_url:
            by_base_url[base_url] = {}

        if path not in by_base_url[base_url]:
            by_base_url[base_url][path] = {
                'path': path,
                'methods': [],
                'parameters': {
                    'query': [],
                    'body': [],
                    'path': []
                },
                'sample_urls': [action_url],
                'urls_found': 1
            }

        endpoint = by_base_url[base_url][path]

        # Add method if not present
        if method not in endpoint['methods']:
            endpoint['methods'].append(method)

        # Add body parameters from form inputs
        for input_field in form['inputs']:
            if input_field['type'] in ['submit', 'button', 'hidden', 'image']:
                continue

            existing_param = next(
                (p for p in endpoint['parameters']['body'] if p['name'] == input_field['name']),
                None
            )

            if not existing_param:
                param_info = {
                    'name': input_field['name'],
                    'type': infer_parameter_type(input_field['name'], []),
                    'input_type': input_field['type'],
                    'required': input_field.get('required', False),
                    'category': classify_parameter(input_field['name'])
                }
                endpoint['parameters']['body'].append(param_info)

    # Add classification and finalize endpoints structure
    endpoints_by_base = {}

    for base_url, paths in by_base_url.items():
        endpoints_by_base[base_url] = {
            'base_url': base_url,
            'endpoints': {},
            'summary': {
                'total_endpoints': 0,
                'total_parameters': 0,
                'methods': {},
                'categories': {}
            }
        }

        for path, endpoint in paths.items():
            # Classify endpoint
            category = classify_endpoint(path, endpoint['methods'], endpoint['parameters'])
            endpoint['category'] = category

            # Count parameters
            query_count = len(endpoint['parameters']['query'])
            body_count = len(endpoint['parameters']['body'])
            path_count = len(endpoint['parameters']['path'])
            total_params = query_count + body_count + path_count

            endpoint['parameter_count'] = {
                'query': query_count,
                'body': body_count,
                'path': path_count,
                'total': total_params
            }

            # Remove sample_urls from final output to save space (keep in endpoints)
            endpoints_by_base[base_url]['endpoints'][path] = endpoint

            # Update summary
            endpoints_by_base[base_url]['summary']['total_endpoints'] += 1
            endpoints_by_base[base_url]['summary']['total_parameters'] += total_params

            for method in endpoint['methods']:
                endpoints_by_base[base_url]['summary']['methods'][method] = \
                    endpoints_by_base[base_url]['summary']['methods'].get(method, 0) + 1

            endpoints_by_base[base_url]['summary']['categories'][category] = \
                endpoints_by_base[base_url]['summary']['categories'].get(category, 0) + 1

    return {
        'by_base_url': endpoints_by_base,
        'forms': all_forms
    }

