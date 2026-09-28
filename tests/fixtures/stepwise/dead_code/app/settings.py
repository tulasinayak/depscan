import json

import yaml

DEFAULTS = {"theme": "light", "page_size": 20}


def parse_settings(body):
    values = json.loads(body or b"{}")
    return {k: v for k, v in values.items() if k in DEFAULTS}


def _import_legacy_settings(raw):
    return yaml.full_load(raw)


def dump_settings(values):
    return yaml.safe_dump(values, sort_keys=True)
