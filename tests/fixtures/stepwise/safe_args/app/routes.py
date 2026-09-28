from flask import Blueprint, abort, jsonify, request

from app.inventory import fetch_stock
from app.settings import load_defaults, parse_settings

bp = Blueprint("shop", __name__)
SETTINGS = load_defaults("defaults.yaml")


@bp.post("/settings")
def update_settings():
    values = parse_settings(request.data)
    if not isinstance(values, dict):
        abort(400)
    SETTINGS.update(values)
    return jsonify(sorted(SETTINGS))


@bp.get("/stock/<int:sku>")
def stock(sku):
    return jsonify(fetch_stock(sku))
