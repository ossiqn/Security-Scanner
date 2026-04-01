import os
import logging
from flask import Flask, render_template, jsonify, request, abort

PRODUCER = "OSSiqn"
logger = logging.getLogger("scanline.web")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()

_db = None
_scanner_status = {
    "running": False,
    "current_task": "",
    "total_findings": 0,
    "scan_start": None,
    "produced_by": "OSSiqn"
}

_clients = []


def init_web(db, scanner_status: dict):
    global _db, _scanner_status
    _db = db
    _scanner_status = scanner_status
    _scanner_status["produced_by"] = "OSSiqn"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/findings")
def get_findings():
    if not _db:
        return jsonify({"error": "Database not initialized"}), 500

    limit    = min(int(request.args.get("limit", 100)), 1000)
    offset   = int(request.args.get("offset", 0))
    severity = request.args.get("severity") or None
    source   = request.args.get("source") or None

    findings = _db.get_findings(
        limit=limit,
        offset=offset,
        severity=severity,
        source=source
    )

    return jsonify({
        "findings":    findings,
        "count":       len(findings),
        "offset":      offset,
        "produced_by": PRODUCER
    })


@app.route("/api/stats")
def get_stats():
    if not _db:
        return jsonify({"error": "Database not initialized"}), 500

    stats = _db.get_stats()
    stats["scanner_status"] = _scanner_status
    stats["produced_by"]    = PRODUCER
    stats["tool"]           = "ScanLine by OSSiqn"

    return jsonify(stats)


@app.route("/api/findings/<int:finding_id>/false_positive", methods=["POST"])
def mark_false_positive(finding_id):
    if not _db:
        abort(500)
    _db.mark_false_positive(finding_id)
    return jsonify({
        "success":     True,
        "finding_id":  finding_id,
        "produced_by": PRODUCER
    })


@app.route("/api/status")
def get_status():
    return jsonify({**_scanner_status, "produced_by": PRODUCER})


@app.route("/api/info")
def get_info():
    return jsonify({
        "tool":        "ScanLine",
        "version":     "1.0.0",
        "produced_by": "OSSiqn",
        "github":      "https://github.com/ossiqn",
        "license":     "MIT © 2024 OSSiqn"
    })


def broadcast_finding(finding: dict):
    finding["produced_by"] = PRODUCER


def broadcast_status(status: dict):
    status["produced_by"] = PRODUCER


def run_web(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    logger.info(f"[OSSiqn Web] Dashboard starting on http://{host}:{port}")
    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=False,
        threaded=True
    )
