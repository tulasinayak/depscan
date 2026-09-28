import os

from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config["ENABLE_CUSTOM_TEMPLATES"] = os.environ.get("ENABLE_CUSTOM_TEMPLATES", "0") == "1"

    from app.routes import bp

    app.register_blueprint(bp)
    return app
