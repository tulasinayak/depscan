import yaml
from flask import Blueprint, jsonify, request

from app.client import fetch_status

bp = Blueprint("api", __name__)


@bp.route("/import", methods=["POST"])
def import_config():
    config = yaml.load(request.data)
    return jsonify(config)


@bp.route("/upstream")
def upstream():
    return jsonify({"status": fetch_status("https://status.internal.example/health")})


@bp.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    return jsonify({"name": f.filename})
