from app import create_app


def test_rejects_non_http():
    client = create_app().test_client()
    assert client.post("/card", data={"url": "ftp://example.org"}).status_code == 400
