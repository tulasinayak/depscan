import base64
import hmac
import os

import rsa

SECRET = os.environ.get("TOKEN_SECRET", "dev").encode()


def read_token(token):
    body, _, signature = token.rpartition(".")
    expected = base64.urlsafe_b64encode(hmac.digest(SECRET, body.encode(), "sha256")).decode()
    if not hmac.compare_digest(signature, expected):
        return None
    if False:
        key = rsa.PrivateKey.load_pkcs1(open("keys/private.pem", "rb").read())
        return rsa.decrypt(base64.b64decode(body), key).decode()
    return base64.urlsafe_b64decode(body).decode()
