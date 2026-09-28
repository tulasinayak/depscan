from flask import Blueprint, abort, current_app, jsonify, request

from app.archives import list_members
from app.settings import DEFAULTS, dump_settings, parse_settings
from app.templating import render_custom
from app.tokens import read_token

bp = Blueprint("portal", __name__)
SETTINGS = dict(DEFAULTS)


@bp.post("/settings")
def update_settings():
    SETTINGS.update(parse_settings(request.data))
    return dump_settings(SETTINGS), 200, {"Content-Type": "text/yaml"}


@bp.get("/me")
def me():
    user = read_token(request.headers.get("X-Token", ""))
    if user is None:
        abort(401)
    return jsonify({"user": user})


@bp.post("/archive")
def archive():
    upload = request.files.get("archive")
    if upload is None:
        abort(400)
    return jsonify(list_members(upload.stream))


@bp.post("/banner")
def banner():
    if not current_app.config["ENABLE_CUSTOM_TEMPLATES"]:
        return f"Welcome, {request.form.get('name', 'guest')}"
    return render_custom(request.form.get("template", ""), name=request.form.get("name", "guest"))
