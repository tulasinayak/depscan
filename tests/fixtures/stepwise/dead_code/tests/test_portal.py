from app import create_app


def test_settings_roundtrip():
    client = create_app().test_client()
    assert b"page_size: 50" in client.post("/settings", data=b'{"page_size": 50}').data
