from app.settings import parse_settings


def test_parse_settings():
    assert parse_settings(b"page_size: 50\n") == {"page_size": 50}
