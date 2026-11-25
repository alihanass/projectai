import math
import os
import re
import sqlite3
from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

import database as db
from search_engine import ALGORITHMS, CIA_LEVELS, run_search, severity_from_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
db.init_db()


@app.before_request
def handle_cors_preflight():
    if request.method == "OPTIONS":
        resp = app.make_response(("", 204))
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, PUT, DELETE, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return resp


@app.after_request
def add_response_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, PUT, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    if request.path == "/" or request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def bounded_int(value, default, minimum, maximum):
    try:
        return max(minimum, min(maximum, int(value)))
    except (TypeError, ValueError):
        return default


def resolve_patched(data, graph):
    """Uses explicit patched list if supplied, otherwise active DB state."""
    if "patched" in data and isinstance(data["patched"], list):
        valid_ids = {e["id"] for e in graph["edges"]}
        return [eid for eid in data["patched"] if eid in valid_ids]
    return graph["patchedEdges"]


@app.errorhandler(Exception)
def handle_api_error(err):
    if isinstance(err, HTTPException):
        return err
    if request.path.startswith("/api/"):
        return jsonify({"error": str(err)}), 500
    raise err


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "database": db.db_stats()})


@app.route("/api/graph")
def get_graph():
    return jsonify(db.fetch_graph())


def find_clean_node_position(nodes, connect_from=None, connect_to=None):
    node_map = {n["id"]: n for n in nodes}
    if connect_from in node_map and connect_to in node_map:
        ax = (node_map[connect_from]["x"] + node_map[connect_to]["x"]) / 2.0
        ay = (node_map[connect_from]["y"] + node_map[connect_to]["y"]) / 2.0
    elif connect_from in node_map:
        ax = min(780.0, node_map[connect_from]["x"] + 135.0)
        ay = float(node_map[connect_from]["y"])
    elif connect_to in node_map:
        ax = max(95.0, node_map[connect_to]["x"] - 135.0)
        ay = float(node_map[connect_to]["y"])
    else:
        ax, ay = 440.0, 215.0

    candidates = []
    # Concentric rings around preferred anchor
    for radius in (0, 65, 110, 155, 200):
        steps = 1 if radius == 0 else 12
        for k in range(steps):
            ang = (2 * math.pi * k) / steps
            cx = round(max(72, min(808, ax + radius * math.cos(ang))))
            cy = round(max(56, min(368, ay + radius * math.sin(ang))))
            candidates.append((cx, cy))
    # Fallback full-canvas grid
    for gx in range(90, 800, 70):
        for gy in range(65, 365, 65):
            candidates.append((gx, gy))

    best_pos = (440, 215)
    best_score = -1e9
    for cx, cy in candidates:
        min_dist = min((math.hypot(cx - n["x"], cy - n["y"]) for n in nodes), default=999.0)
        anchor_dist = math.hypot(cx - ax, cy - ay)
        # Prefer clear spots (>= 92px from every node) closest to anchor
        if min_dist >= 92:
            score = 10000.0 - anchor_dist + min(min_dist, 160.0) * 0.5
        else:
            score = min_dist * 10.0 - anchor_dist * 0.2
        if score > best_score:
            best_score = score
            best_pos = (cx, cy)
    return int(best_pos[0]), int(best_pos[1])


@app.route("/api/nodes", methods=["POST"])
def create_node():
    data = request.get_json(silent=True) or {}
    raw_short = str(data.get("shortName") or data.get("tag") or data.get("id") or "").strip()
    label = str(data.get("label") or "").strip()
    if not raw_short or len(raw_short) > 20:
        return jsonify({"error": "Node ID / Short Name is required (1–20 chars)"}), 400
    if not label or len(label) > 40:
        return jsonify({"error": "Display Label is required (1–40 chars)"}), 400

    node_id = re.sub(r"[^a-z0-9_]+", "_", raw_short.lower()).strip("_")
    if not node_id:
        return jsonify({"error": "Node ID must contain letters or numbers"}), 400

    tag = raw_short.upper()[:6]
    h_val = bounded_int(data.get("h"), 3, 0, 50)
    edge_cost = bounded_int(data.get("cost"), 3, 1, 20)
    connect_from = str(data.get("connectFrom") or "").strip() or None
    connect_to = str(data.get("connectTo") or "").strip() or None

    graph = db.fetch_graph()
    existing_ids = {n["id"] for n in graph["nodes"]}
    if node_id in existing_ids:
        return jsonify({"error": f"Node '{raw_short}' already exists"}), 409
    if connect_from and connect_from not in existing_ids:
        return jsonify({"error": f"Invalid 'Connect From' node '{connect_from}'"}), 400
    if connect_to and connect_to not in existing_ids:
        return jsonify({"error": f"Invalid 'Connect To' node '{connect_to}'"}), 400

    x = data.get("x")
    y = data.get("y")
    if x is not None and y is not None:
        px = bounded_int(x, 440, 52, 828)
        py = bounded_int(y, 215, 48, 372)
    else:
        px, py = find_clean_node_position(graph["nodes"], connect_from, connect_to)

    node_data = {
        "id": node_id,
        "label": label,
        "kuLabel": label,
        "role": "Custom",
        "kuRole": "گرێی زیادکراو",
        "tag": tag,
        "x": px,
        "y": py,
        "h": h_val,
    }

    existing_edge_ids = {e["id"] for e in graph["edges"]}
    next_num = len(existing_edge_ids) + 1

    def alloc_edge_id():
        nonlocal next_num
        while f"e{next_num}" in existing_edge_ids:
            next_num += 1
        eid = f"e{next_num}"
        existing_edge_ids.add(eid)
        return eid

    def build_edge(src, dst):
        cvss = 7.5
        return {
            "id": alloc_edge_id(),
            "from": src,
            "to": dst,
            "cost": edge_cost,
            "vuln": "Lateral Pivot",
            "cvss": cvss,
            "severity": severity_from_score(cvss),
            "vector": "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L",
            "cia": {"c": "High", "i": "High", "a": "Low"},
            "technique": {
                "en": f"Lateral Network Exploit Path ({src} → {dst})",
                "ku": f"ڕێگای قۆستنەوەی ناوخۆیی نێتۆرک ({src} → {dst})",
            },
            "policy": {
                "en": "Zero-Trust Segmentation & Least Privilege Access Policy",
                "ku": "سیاسەتی دابەشکردنی نێتۆرکی Zero-Trust و کەمترین دەسەڵات",
            },
            "mechanism": {
                "en": "Network Micro-Segmentation, MFA & Endpoint Detection and Response (EDR)",
                "ku": "جیاکردنەوەی وردی نێتۆرک، پشتڕاستکردنەوەی MFA و سیستەمی EDR",
            },
        }

    new_edges = []
    if connect_from:
        new_edges.append(build_edge(connect_from, node_id))
    if connect_to:
        new_edges.append(build_edge(node_id, connect_to))

    try:
        created_node, created_edges = db.create_node_with_edges(node_data, new_edges)
    except sqlite3.IntegrityError:
        return jsonify({"error": f"Node '{raw_short}' already exists"}), 409

    return jsonify({"node": created_node, "edges": created_edges, "graph": db.fetch_graph()}), 201


@app.route("/api/nodes/<node_id>/position", methods=["PATCH"])
def move_node(node_id):
    data = request.get_json(silent=True) or {}
    x = bounded_int(data.get("x"), 440, 52, 828)
    y = bounded_int(data.get("y"), 215, 48, 372)
    updated = db.update_node_position(node_id, x, y)
    if updated is None:
        return jsonify({"error": f"Unknown node '{node_id}'"}), 404
    return jsonify({"node": updated})


@app.route("/api/edges/<edge_id>/patch", methods=["PATCH", "POST"])
def toggle_or_set_patch(edge_id):
    graph_before = db.fetch_graph()
    edge_before = next((e for e in graph_before["edges"] if e["id"] == edge_id), None)
    if edge_before is None:
        return jsonify({"error": f"Unknown vulnerability edge '{edge_id}'"}), 404

    data = request.get_json(silent=True) or {}
    start_id = str(data.get("start", "internet"))
    goal_id = str(data.get("goal", "core_db"))
    node_ids = {n["id"] for n in graph_before["nodes"]}
    if start_id not in node_ids:
        start_id = "internet"
    if goal_id not in node_ids:
        goal_id = "core_db"

    target_state = (not edge_before["isPatched"]) if "patched" not in data else bool(data["patched"])

    res_before = run_search(
        "ASTAR", start_id, goal_id, graph_before["nodes"], graph_before["edges"], patched=graph_before["patchedEdges"]
    )
    updated_edge = db.set_edge_patched(edge_id, target_state)
    graph_after = db.fetch_graph()
    res_after = run_search(
        "ASTAR", start_id, goal_id, graph_after["nodes"], graph_after["edges"], patched=graph_after["patchedEdges"]
    )

    action = "PATCHED" if target_state else "REOPENED"
    note = (
        f'{updated_edge["from"]} -> {updated_edge["to"]} | '
        f'CVSS {updated_edge["cvss"]:.1f} ({updated_edge["severity"]})'
    )
    log_entry = db.add_mitigation_log(
        edge_id=updated_edge["id"],
        vuln=updated_edge["vuln"],
        action=action,
        note=note,
        risk_before=res_before["riskScore"],
        risk_after=res_after["riskScore"],
    )

    return jsonify(
        {
            "edge": updated_edge,
            "patchedEdges": graph_after["patchedEdges"],
            "riskBefore": res_before["riskScore"],
            "riskAfter": res_after["riskScore"],
            "log": log_entry,
            "stats": db.db_stats(),
        }
    )


@app.route("/api/edges/<edge_id>", methods=["PATCH"])
def update_edge(edge_id):
    data = request.get_json(silent=True) or {}
    cost = None
    cvss = None
    severity = None
    cia = None

    if "cost" in data:
        cost = bounded_int(data["cost"], 3, 1, 20)
    if "cvss" in data:
        try:
            cvss = round(max(0.1, min(10.0, float(data["cvss"]))), 1)
            severity = severity_from_score(cvss)
        except (TypeError, ValueError):
            return jsonify({"error": "Invalid CVSS score"}), 400
    if "cia" in data and isinstance(data["cia"], dict):
        cia = {}
        for pillar in ("c", "i", "a"):
            if pillar in data["cia"]:
                val = str(data["cia"][pillar]).capitalize()
                if val not in CIA_LEVELS:
                    return jsonify({"error": f"Invalid CIA level for {pillar}"}), 400
                cia[pillar] = val

    updated = db.update_edge_fields(edge_id, cost=cost, cvss=cvss, severity=severity, cia=cia)
    if updated is None:
        return jsonify({"error": f"Unknown vulnerability edge '{edge_id}'"}), 404

    db.add_mitigation_log(
        edge_id=updated["id"],
        vuln=updated["vuln"],
        action="EDGE_UPDATED",
        note=f'Updated cost={updated["cost"]}, CVSS={updated["cvss"]:.1f} ({updated["severity"]})',
    )
    return jsonify({"edge": updated})


@app.route("/api/edges/restore", methods=["POST"])
def restore_edges():
    data = request.get_json(silent=True) or {}
    graph_before = db.fetch_graph()
    start_id = str(data.get("start", "internet"))
    goal_id = str(data.get("goal", "core_db"))
    node_ids = {n["id"] for n in graph_before["nodes"]}
    if start_id not in node_ids:
        start_id = "internet"
    if goal_id not in node_ids:
        goal_id = "core_db"

    res_before = run_search(
        "ASTAR", start_id, goal_id, graph_before["nodes"], graph_before["edges"], patched=graph_before["patchedEdges"]
    )
    db.restore_all_edges()
    graph_after = db.fetch_graph()
    res_after = run_search(
        "ASTAR", start_id, goal_id, graph_after["nodes"], graph_after["edges"], patched=graph_after["patchedEdges"]
    )
    log_entry = db.add_mitigation_log(
        edge_id=None,
        vuln="All 17 Vulnerabilities",
        action="RESTORED_ALL",
        note="Network reset to baseline unpatched topology",
        risk_before=res_before["riskScore"],
        risk_after=res_after["riskScore"],
    )
    return jsonify(
        {
            "patchedEdges": [],
            "log": log_entry,
            "stats": db.db_stats(),
        }
    )


@app.route("/api/search", methods=["POST"])
def search():
    data = request.get_json(silent=True) or {}
    graph = db.fetch_graph()
    node_ids = {n["id"] for n in graph["nodes"]}

    algo = str(data.get("algo", "ASTAR")).upper()
    start_id = str(data.get("start", "internet"))
    goal_id = str(data.get("goal", "core_db"))
    dls_limit = bounded_int(data.get("dlsLimit"), 2, 1, 10)
    save_run = bool(data.get("save", True))

    if algo not in ALGORITHMS or start_id not in node_ids or goal_id not in node_ids:
        return jsonify({"error": "Invalid algorithm, start node, or goal node"}), 400

    patched = resolve_patched(data, graph)
    result = run_search(algo, start_id, goal_id, graph["nodes"], graph["edges"], dls_limit, patched)

    run_id = None
    if save_run:
        run_id = db.record_search_run(result, start_id, goal_id, dls_limit, len(patched))

    result["runId"] = run_id
    return jsonify(result)


@app.route("/api/benchmark", methods=["POST"])
def benchmark():
    data = request.get_json(silent=True) or {}
    graph = db.fetch_graph()
    node_ids = {n["id"] for n in graph["nodes"]}

    start_id = str(data.get("start", "internet"))
    goal_id = str(data.get("goal", "core_db"))
    dls_limit = bounded_int(data.get("dlsLimit"), 2, 1, 10)

    if start_id not in node_ids or goal_id not in node_ids:
        return jsonify({"error": "Invalid start or goal node"}), 400

    patched = resolve_patched(data, graph)
    results = []
    for algo in ALGORITHMS:
        r = run_search(algo, start_id, goal_id, graph["nodes"], graph["edges"], dls_limit, patched)
        # Omit verbose per-step trace in bulk benchmark payload for lean responses
        r.pop("steps", None)
        results.append(r)

    return jsonify({"results": results, "patchedCount": len(patched)})


@app.route("/api/history", methods=["GET", "DELETE"])
def history():
    if request.method == "DELETE":
        db.clear_search_history()
        return jsonify({"cleared": True, "stats": db.db_stats()})
    limit = bounded_int(request.args.get("limit"), 25, 1, 100)
    return jsonify({"history": db.fetch_search_history(limit)})


@app.route("/api/logs", methods=["GET"])
def logs():
    limit = bounded_int(request.args.get("limit"), 30, 1, 100)
    return jsonify({"logs": db.fetch_mitigation_logs(limit)})


@app.route("/api/scenarios", methods=["GET", "POST"])
def scenarios():
    if request.method == "GET":
        return jsonify({"scenarios": db.fetch_scenarios()})

    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name or len(name) > 80:
        return jsonify({"error": "Scenario name is required (1–80 chars)"}), 400

    description = str(data.get("description", "")).strip()[:240]
    graph = db.fetch_graph()
    node_ids = {n["id"] for n in graph["nodes"]}
    start_id = str(data.get("start", "internet"))
    goal_id = str(data.get("goal", "core_db"))
    algo = str(data.get("algo", "ASTAR")).upper()
    dls_limit = bounded_int(data.get("dlsLimit"), 2, 1, 10)

    if start_id not in node_ids or goal_id not in node_ids or algo not in ALGORITHMS:
        return jsonify({"error": "Invalid scenario parameters"}), 400

    patched = resolve_patched(data, graph)
    eval_res = run_search("ASTAR", start_id, goal_id, graph["nodes"], graph["edges"], dls_limit, patched)

    try:
        scenario = db.create_scenario(
            name=name,
            description=description,
            start_node=start_id,
            goal_node=goal_id,
            algo=algo,
            dls_limit=dls_limit,
            patched_edges=patched,
            risk_score=eval_res["riskScore"],
            risk_severity=eval_res["riskSeverity"],
        )
    except sqlite3.IntegrityError:
        return jsonify({"error": "A scenario with that name already exists"}), 409

    return jsonify({"scenario": scenario, "stats": db.db_stats()}), 201


@app.route("/api/scenarios/<int:scenario_id>/load", methods=["POST"])
def load_scenario(scenario_id):
    scenario = db.get_scenario(scenario_id)
    if scenario is None:
        return jsonify({"error": "Scenario not found"}), 404

    graph_before = db.fetch_graph()
    res_before = run_search(
        "ASTAR",
        scenario["start_node"],
        scenario["goal_node"],
        graph_before["nodes"],
        graph_before["edges"],
        patched=graph_before["patchedEdges"],
    )

    db.apply_patched_set(scenario["patchedEdges"])
    graph_after = db.fetch_graph()
    res_after = run_search(
        "ASTAR",
        scenario["start_node"],
        scenario["goal_node"],
        graph_after["nodes"],
        graph_after["edges"],
        patched=graph_after["patchedEdges"],
    )

    log_entry = db.add_mitigation_log(
        edge_id=None,
        vuln=scenario["name"],
        action="SCENARIO_LOADED",
        note=f'Loaded {len(graph_after["patchedEdges"])} patched edges',
        risk_before=res_before["riskScore"],
        risk_after=res_after["riskScore"],
    )

    return jsonify(
        {
            "scenario": scenario,
            "patchedEdges": graph_after["patchedEdges"],
            "log": log_entry,
            "stats": db.db_stats(),
        }
    )


@app.route("/api/scenarios/<int:scenario_id>", methods=["DELETE"])
def remove_scenario(scenario_id):
    if not db.delete_scenario(scenario_id):
        return jsonify({"error": "Scenario not found"}), 404
    return jsonify({"deleted": True, "stats": db.db_stats()})


if __name__ == "__main__":
    print("CyberShield AI Backend + SQLite DB running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
