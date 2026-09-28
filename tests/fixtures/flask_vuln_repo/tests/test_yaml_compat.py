import yaml


def test_legacy_loader():
    assert yaml.load("a: 1") == {"a": 1}
