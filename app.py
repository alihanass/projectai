import os
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
