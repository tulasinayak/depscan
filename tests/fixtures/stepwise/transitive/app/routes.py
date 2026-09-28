from flask import Blueprint, abort, jsonify, request

from app.preview import fetch_preview

bp = Blueprint("cards", __name__)


@bp.post("/card")
def make_card():
    url = request.form.get("url", "").strip()
    if not url.startswith(("http://", "https://")):
        abort(400)
    return jsonify(fetch_preview(url))
