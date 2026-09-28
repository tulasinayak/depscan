from flask import Flask

from app.inventory import warm_up


def create_app(check_upstream=True):
    app = Flask(__name__)
    if check_upstream:
        warm_up()

    from app.routes import bp

    app.register_blueprint(bp)
    return app
