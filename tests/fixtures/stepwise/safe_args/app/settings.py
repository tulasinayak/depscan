import yaml


def parse_settings(body):
    return yaml.load(body, Loader=yaml.SafeLoader)


def load_defaults(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)
