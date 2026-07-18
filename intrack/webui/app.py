"""
INtrack Dashboard — Flask backend + UI, bolted directly into the INtrack repo

Lives at INtrack/webui/app.py. Serves the dashboard UI AND wraps the real
`intrack` CLI as a subprocess per scan — one command runs both.

Setup (run once, from the INtrack repo root):
    pip install -e .                    # installs the `intrack` command, pointed at THIS local copy
    cd webui
    pip install -r requirements.txt

Run (from webui/):
    python app.py
    -> open http://localhost:5000 in a browser
"""

import json
import os
import queue
import shlex
import shutil
import subprocess
import threading
import uuid

from flask import Flask, Response, jsonify, request, send_file, send_from_directory, stream_with_context
from flask_cors import CORS

import db

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)
db.init_db()


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")



# ---------------------------------------------------------------------------
# In-memory scan registry. Fine for a local single-user tool; swap for Redis
# if this ever needs to survive a backend restart or run multi-user.
# ---------------------------------------------------------------------------
SCANS = {}  # scan_id -> {"proc": Popen, "queue": Queue, "status": str, "results": [...]}
SCANS_LOCK = threading.Lock()

# Maps the JSON keys the dashboard form sends -> actual intrack CLI flags.
# Keeping this table explicit (rather than guessing from the key name) means
# the frontend and backend can never silently drift out of sync.
FLAG_MAP = {
    "host":          "-H",
    "file":          "-f",
    "n_targets":     "-n",
    "port":          "-p",
    "threads":       "-t",
    "output_file":   "-o",
    "lhost":         "-L",
    "lport":         "-P",
    "instance":      "-i",
    "backdoor":      "-b",
    "worm":          "-w",
    "vuln":          "-v",
    "exposure":      "-e",
    "iot":           "--iot",
    "miscellaneous": "-m",
    "workflows":     "--workflows",
    "network":       "-N",
    "timeout":       "--timeout",
    "spider":        "-s",
    "bar_style":     "--bar-style",
}
# Boolean/flag-only options (no value follows them)
FLAG_ONLY = {"hostname": "--hostname", "probe": "--probe"}


def build_argv(config: dict) -> list[str]:
    """
    Turn the dashboard's JSON config into the exact argv intrack's CLI expects.
    This is the single source of truth both the 'Run Scan' button and the
    'CLI Mode' equivalent-command view should agree with.
    """
    binary = shutil.which("intrack")
    if not binary:
        raise RuntimeError(
            "The 'intrack' binary isn't on PATH. From the repo root, run: "
            "pip install -e .   (then restart this server)"
        )

    argv = [binary]

    for key, flag in FLAG_MAP.items():
        value = config.get(key)
        if value in (None, "", []):
            continue
        argv += [flag, str(value)]

    for key, flag in FLAG_ONLY.items():
        if config.get(key):
            argv.append(flag)

    if config.get("proxychains"):
        proxychains_bin = shutil.which("proxychains4") or shutil.which("proxychains")
        if not proxychains_bin:
            raise RuntimeError(
                "Proxychains was enabled but proxychains4/proxychains isn't installed."
            )
        argv = [proxychains_bin] + argv

    return argv


def equivalent_command_string(config: dict) -> str:
    """Human-readable command for the dashboard's CLI Mode panel."""
    try:
        argv = build_argv(config)
    except RuntimeError as e:
        return f"# {e}"
    return " ".join(shlex.quote(a) for a in argv)


def _reader_thread(scan_id: str, proc: subprocess.Popen):
    """Reads the subprocess's stdout line by line, pushes it onto the scan's
    queue for live streaming, and accumulates it so the final result can be
    written to SQLite once the process exits."""
    q = SCANS[scan_id]["queue"]
    lines = []
    found_count = 0
    try:
        for line in iter(proc.stdout.readline, ""):
            if not line:
                break
            clean = line.rstrip("\n")
            lines.append(clean)
            if "[+]" in clean:
                found_count += 1
            q.put({"type": "line", "data": clean})
    finally:
        proc.stdout.close()
        return_code = proc.wait()
        status = "completed" if return_code == 0 else "failed"
        with SCANS_LOCK:
            SCANS[scan_id]["status"] = status
        db.finish_scan(scan_id, status, return_code, found_count, "\n".join(lines))
        q.put({"type": "done", "returncode": return_code, "found_count": found_count})


@app.route("/api/scan/preview", methods=["POST"])
def preview_command():
    """Used by CLI Mode to show the equivalent command without running it."""
    config = request.get_json(force=True) or {}
    return jsonify({"command": equivalent_command_string(config)})


@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    config = request.get_json(force=True) or {}

    if not any(config.get(k) for k in ("host", "file", "n_targets")):
        return jsonify({"error": "One of host, file, or n_targets is required."}), 400

    try:
        argv = build_argv(config)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400

    scan_id = str(uuid.uuid4())

    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,  # line-buffered
    )

    with SCANS_LOCK:
        SCANS[scan_id] = {
            "proc": proc,
            "queue": queue.Queue(),
            "status": "running",
            "command": " ".join(shlex.quote(a) for a in argv),
        }

    db.create_scan(scan_id, SCANS[scan_id]["command"], config, config.get("output_file") or None)

    threading.Thread(target=_reader_thread, args=(scan_id, proc), daemon=True).start()

    return jsonify({"scan_id": scan_id, "command": SCANS[scan_id]["command"]}), 201


@app.route("/api/scan/<scan_id>/stream")
def stream_scan(scan_id):
    """Server-Sent Events endpoint — the dashboard's Live Output console
    subscribes here and appends each line as it arrives."""
    if scan_id not in SCANS:
        return jsonify({"error": "unknown scan_id"}), 404

    def generate():
        q = SCANS[scan_id]["queue"]
        while True:
            event = q.get()
            yield f"data: {json.dumps(event)}\n\n"
            if event["type"] == "done":
                break

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/api/scan/<scan_id>/stop", methods=["POST"])
def stop_scan(scan_id):
    entry = SCANS.get(scan_id)
    if not entry:
        return jsonify({"error": "unknown scan_id"}), 404

    proc = entry["proc"]
    if proc.poll() is None:  # still running
        proc.terminate()
        with SCANS_LOCK:
            entry["status"] = "stopped"
        db.mark_scan_stopped(scan_id)

    return jsonify({"status": entry["status"]})


@app.route("/api/scan/<scan_id>/status")
def scan_status(scan_id):
    entry = SCANS.get(scan_id)
    if not entry:
        return jsonify({"error": "unknown scan_id"}), 404
    return jsonify({"status": entry["status"], "command": entry["command"]})


@app.route("/api/scanners")
def list_scanners():
    """Shells out to `intrack --list` so the scanner-type panel always
    reflects whatever scanners actually exist in the installed package,
    instead of a hardcoded list that goes stale."""
    binary = shutil.which("intrack")
    if not binary:
        return jsonify({"error": "intrack binary not found on PATH"}), 500

    result = subprocess.run([binary, "--list"], capture_output=True, text=True, timeout=15)
    return jsonify({"output": result.stdout})


@app.route("/api/health")
def health():
    proxychains_available = bool(shutil.which("proxychains4") or shutil.which("proxychains"))
    return jsonify({
        "intrack_installed": bool(shutil.which("intrack")),
        "proxychains_available": proxychains_available,
    })


# ---------------------------------------------------------------- Past Results

@app.route("/api/history")
def history_list():
    return jsonify({"scans": db.list_scans()})


@app.route("/api/history/<scan_id>")
def history_detail(scan_id):
    scan = db.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "unknown scan_id"}), 404
    return jsonify(scan)


@app.route("/api/history/<scan_id>", methods=["DELETE"])
def history_delete(scan_id):
    db.delete_scan(scan_id)
    return jsonify({"deleted": scan_id})


# --------------------------------------------------------------------- Exports

@app.route("/api/exports")
def exports_list():
    return jsonify({"exports": db.list_exports()})


@app.route("/api/exports/<scan_id>/download")
def exports_download(scan_id):
    scan = db.get_scan(scan_id)
    if not scan or not scan.get("output_file"):
        return jsonify({"error": "no output file recorded for this scan"}), 404

    path = scan["output_file"]
    if not os.path.isabs(path):
        path = os.path.abspath(path)

    if not os.path.exists(path):
        return jsonify({"error": f"file no longer exists on disk: {path}"}), 404

    return send_file(path, as_attachment=True)


# -------------------------------------------------------------------- Targets

@app.route("/api/targets", methods=["GET"])
def targets_list():
    return jsonify({"targets": db.list_targets()})


@app.route("/api/targets", methods=["POST"])
def targets_create():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    kind = data.get("kind")
    value = (data.get("value") or "").strip()

    if not name or not value or kind not in ("host", "file"):
        return jsonify({"error": "name, value, and kind ('host' or 'file') are required"}), 400

    target_id = db.create_target(name, kind, value)
    return jsonify({"id": target_id}), 201


@app.route("/api/targets/<target_id>", methods=["DELETE"])
def targets_delete(target_id):
    db.delete_target(target_id)
    return jsonify({"deleted": target_id})


# ------------------------------------------------------------------- Settings

@app.route("/api/settings", methods=["GET"])
def settings_get():
    return jsonify(db.get_settings())


@app.route("/api/settings", methods=["POST"])
def settings_update():
    data = request.get_json(force=True) or {}
    allowed = {"threads", "timeout", "bar_style", "proxychains", "port", "scan_type", "hostname"}
    values = {k: v for k, v in data.items() if k in allowed}
    if not values:
        return jsonify({"error": f"no valid settings keys provided (allowed: {sorted(allowed)})"}), 400
    db.update_settings(values)
    return jsonify(db.get_settings())


if __name__ == "__main__":
    app.run(debug=True, port=5000)
