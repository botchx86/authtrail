"""Strict JSON configuration; command-line values override saved settings."""
import ipaddress
import json

DEFAULTS = dict(window=300, failures=5, users=5, distributed_sources=5,
                distributed_failures=10, distributed_window=300, incident_gap=300,
                exclude_source=[], exclude_user=[])


def load_config(path):
    if path is None:
        return dict(DEFAULTS)
    with open(path, encoding='utf-8') as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError('configuration must be a JSON object')
    unknown = set(data) - DEFAULTS.keys()
    if unknown:
        raise ValueError(f'unknown configuration keys: {", ".join(sorted(unknown))}')
    settings = dict(DEFAULTS, **data)
    for key, value in settings.items():
        if key.startswith('exclude_'):
            if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
                raise ValueError(f'{key} must be a list of nonempty strings')
        elif type(value) is not int or value < 1:
            raise ValueError(f'{key} must be a positive integer')
    for source in settings['exclude_source']:
        ipaddress.ip_network(source, strict=False)
    return settings
