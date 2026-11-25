import math

ALGORITHMS = ("BFS", "DFS", "DLS", "IDDFS", "GREEDY", "ASTAR")
CIA_LEVELS = ("High", "Medium", "Low")


def severity_from_score(score):
    if score <= 0:
        return "Secured"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def cia_rank(level):
    return 3 if level == "High" else 2 if level == "Medium" else 1 if level == "Low" else 0


def cia_from_rank(rank):
    return "High" if rank >= 3 else "Medium" if rank == 2 else "Low" if rank == 1 else "Secured"


def get_path_edges(path, edges, patched_set):
    if not path or len(path) < 2:
        return []
    result = []
    for i in range(len(path) - 1):
        src, dst = path[i], path[i + 1]
        match = next(
            (e for e in edges if e["from"] == src and e["to"] == dst and e["id"] not in patched_set),
            None,
        )
        if match is None:
            match = next((e for e in edges if e["from"] == src and e["to"] == dst), None)
        if match is not None:
            result.append(match)
    return result


def evaluate_path_security(path, edges, patched_set=None):
    patched_set = set(patched_set or [])
    path_edges = get_path_edges(path, edges, patched_set)
    if not path_edges:
        return {
            "hasPath": False,
            "edgeIds": [],
            "riskScore": 0.0,
            "severity": "Secured",
            "peakCvss": 0.0,
            "avgCvss": 0.0,
            "cia": {
                "c": {"level": "Secured", "pct": 0, "high": 0, "med": 0, "low": 0},
                "i": {"level": "Secured", "pct": 0, "high": 0, "med": 0, "low": 0},
                "a": {"level": "Secured", "pct": 0, "high": 0, "med": 0, "low": 0},
            },
        }

    scores = [float(e["cvss"]) for e in path_edges]
    peak_cvss = max(scores)
    avg_cvss = sum(scores) / len(scores)
    risk_score = min(10.0, round(0.6 * peak_cvss + 0.4 * avg_cvss, 1))
    severity = severity_from_score(risk_score)

    def summarize_pillar(key):
        max_r = 0
        sum_r = 0
        high = med = low = 0
        for edge in path_edges:
            lvl = edge["cia"][key]
            r = cia_rank(lvl)
            max_r = max(max_r, r)
            sum_r += r
            if lvl == "High":
                high += 1
            elif lvl == "Medium":
                med += 1
            else:
                low += 1
        pct = round(((0.55 * (max_r / 3.0)) + (0.45 * (sum_r / (len(path_edges) * 3.0)))) * 100)
        return {"level": cia_from_rank(max_r), "pct": pct, "high": high, "med": med, "low": low}

    return {
        "hasPath": True,
        "edgeIds": [e["id"] for e in path_edges],
        "riskScore": risk_score,
        "severity": severity,
        "peakCvss": round(peak_cvss, 1),
        "avgCvss": round(avg_cvss, 1),
        "cia": {
            "c": summarize_pillar("c"),
            "i": summarize_pillar("i"),
            "a": summarize_pillar("a"),
        },
    }


def heuristic(node_id, goal_id, node_by_id):
    if node_id == goal_id:
        return 0
    if goal_id == "core_db":
        return int(node_by_id[node_id]["h"])
    a = node_by_id[node_id]
    b = node_by_id[goal_id]
    dist = math.hypot(a["x"] - b["x"], a["y"] - b["y"])
    return max(1, round(dist / 120.0))


def run_search(algo, start_id, goal_id, nodes, edges, dls_limit=2, patched=None):
    patched_set = set(patched if patched is not None else [e["id"] for e in edges if e.get("isPatched")])
    node_by_id = {n["id"]: n for n in nodes}
    steps = []
    expanded = 0
    max_frontier = 1

    def neighbors(nid):
        return [e for e in edges if e["from"] == nid and e["id"] not in patched_set]

    def push(current, visited, frontier, note, found_path=None):
        steps.append(
            {
                "current": current,
                "visited": list(visited),
                "frontier": frontier,
                "note": note,
                "foundPath": found_path,
            }
        )

    def pack(found, status_key, status_arg, path, cost):
        security = evaluate_path_security(path if found else [], edges, patched_set)
        return {
            "algo": algo,
            "found": found,
            "statusKey": status_key,
            "statusArg": status_arg,
            "path": path,
            "cost": cost,
            "hops": (len(path) - 1) if found else None,
            "riskScore": security["riskScore"] if found else 0.0,
            "riskSeverity": security["severity"] if found else "Secured",
            "security": security,
            "expanded": expanded,
            "maxFrontier": max_frontier,
            "steps": steps,
        }

    if algo == "BFS":
        visited = set()
        queue = [{"id": start_id, "path": [start_id], "g": 0}]
        queued = {start_id}
        while queue:
            max_frontier = max(max_frontier, len(queue))
            item = queue.pop(0)
            queued.discard(item["id"])
            if item["id"] in visited:
                continue
            visited.add(item["id"])
            expanded += 1
            if item["id"] == goal_id:
                push(
                    item["id"],
                    visited,
                    [node_by_id[q["id"]]["label"] for q in queue],
                    f'Goal reached at {node_by_id[item["id"]]["label"]} ({len(item["path"]) - 1} hops, cost g={item["g"]})',
                    item["path"],
                )
                return pack(True, "found", None, item["path"], item["g"])
            for edge in neighbors(item["id"]):
                if edge["to"] not in visited and edge["to"] not in queued:
                    queue.append({"id": edge["to"], "path": item["path"] + [edge["to"]], "g": item["g"] + edge["cost"]})
                    queued.add(edge["to"])
            max_frontier = max(max_frontier, len(queue))
            push(
                item["id"],
                visited,
                [node_by_id[q["id"]]["label"] for q in queue],
                f'Expanded {node_by_id[item["id"]]["label"]} (FIFO level {len(item["path"]) - 1})',
            )
        return pack(False, "noPath", None, [], None)

    if algo == "DFS":
        visited = set()
        stack = [{"id": start_id, "path": [start_id], "g": 0}]
        while stack:
            max_frontier = max(max_frontier, len(stack))
            item = stack.pop()
            if item["id"] in visited:
                continue
            visited.add(item["id"])
            expanded += 1
            if item["id"] == goal_id:
                push(
                    item["id"],
                    visited,
                    [node_by_id[s["id"]]["label"] for s in stack],
                    f'Goal reached at {node_by_id[item["id"]]["label"]} (cost g={item["g"]})',
                    item["path"],
                )
                return pack(True, "found", None, item["path"], item["g"])
            for edge in reversed(neighbors(item["id"])):
                if edge["to"] not in visited:
                    stack.append({"id": edge["to"], "path": item["path"] + [edge["to"]], "g": item["g"] + edge["cost"]})
            max_frontier = max(max_frontier, len(stack))
            push(
                item["id"],
                visited,
                [node_by_id[s["id"]]["label"] for s in stack],
                f'Expanded {node_by_id[item["id"]]["label"]} (LIFO depth {len(item["path"]) - 1})',
            )
        return pack(False, "noPath", None, [], None)

    if algo == "DLS":
        stack = [{"id": start_id, "path": [start_id], "g": 0, "depth": 0}]
        visited_any = set()
        cutoff_occurred = False
        while stack:
            max_frontier = max(max_frontier, len(stack))
            item = stack.pop()
            visited_any.add(item["id"])
            expanded += 1
            if item["id"] == goal_id:
                push(
                    item["id"],
                    visited_any,
                    [f'{node_by_id[s["id"]]["label"]}(d={s["depth"]})' for s in stack],
                    f'Goal reached within limit l={dls_limit} (cost g={item["g"]})',
                    item["path"],
                )
                return pack(True, "foundAtL", dls_limit, item["path"], item["g"])
            if item["depth"] < dls_limit:
                for edge in reversed(neighbors(item["id"])):
                    if edge["to"] not in item["path"]:
                        stack.append(
                            {
                                "id": edge["to"],
                                "path": item["path"] + [edge["to"]],
                                "g": item["g"] + edge["cost"],
                                "depth": item["depth"] + 1,
                            }
                        )
                max_frontier = max(max_frontier, len(stack))
                push(
                    item["id"],
                    visited_any,
                    [f'{node_by_id[s["id"]]["label"]}(d={s["depth"]})' for s in stack],
                    f'Expanded {node_by_id[item["id"]]["label"]} at depth {item["depth"]}/{dls_limit}',
                )
            else:
                cutoff_occurred = True
                push(
                    item["id"],
                    visited_any,
                    [f'{node_by_id[s["id"]]["label"]}(d={s["depth"]})' for s in stack],
                    f'Depth cutoff at {node_by_id[item["id"]]["label"]} (l={dls_limit})',
                )
        return pack(False, "cutoff" if cutoff_occurred else "noPath", dls_limit if cutoff_occurred else None, [], None)

    if algo == "IDDFS":
        visited_all = set()
        for limit in range(len(nodes) + 1):
            stack = [{"id": start_id, "path": [start_id], "g": 0, "depth": 0}]
            while stack:
                max_frontier = max(max_frontier, len(stack))
                item = stack.pop()
                visited_all.add(item["id"])
                expanded += 1
                if item["id"] == goal_id:
                    push(
                        item["id"],
                        visited_all,
                        [node_by_id[s["id"]]["label"] for s in stack],
                        f'Goal found at iteration l={limit} (cost g={item["g"]})',
                        item["path"],
                    )
                    return pack(True, "foundAtL", limit, item["path"], item["g"])
                if item["depth"] < limit:
                    for edge in reversed(neighbors(item["id"])):
                        if edge["to"] not in item["path"]:
                            stack.append(
                                {
                                    "id": edge["to"],
                                    "path": item["path"] + [edge["to"]],
                                    "g": item["g"] + edge["cost"],
                                    "depth": item["depth"] + 1,
                                }
                            )
                    max_frontier = max(max_frontier, len(stack))
                push(
                    item["id"],
                    visited_all,
                    [node_by_id[s["id"]]["label"] for s in stack],
                    f'[l={limit}] Visited {node_by_id[item["id"]]["label"]} (depth {item["depth"]})',
                )
        return pack(False, "noPath", None, [], None)

    if algo == "GREEDY":
        visited = set()
        pq = [{"id": start_id, "path": [start_id], "g": 0, "h": heuristic(start_id, goal_id, node_by_id)}]
        while pq:
            max_frontier = max(max_frontier, len(pq))
            pq.sort(key=lambda p: p["h"])
            item = pq.pop(0)
            if item["id"] in visited:
                continue
            visited.add(item["id"])
            expanded += 1
            if item["id"] == goal_id:
                push(
                    item["id"],
                    visited,
                    [f'{node_by_id[p["id"]]["label"]}(h={p["h"]})' for p in pq],
                    f'Goal reached via Greedy! Total cost g={item["g"]}',
                    item["path"],
                )
                return pack(True, "found", None, item["path"], item["g"])
            for edge in neighbors(item["id"]):
                if edge["to"] not in visited:
                    pq.append(
                        {
                            "id": edge["to"],
                            "path": item["path"] + [edge["to"]],
                            "g": item["g"] + edge["cost"],
                            "h": heuristic(edge["to"], goal_id, node_by_id),
                        }
                    )
            max_frontier = max(max_frontier, len(pq))
            push(
                item["id"],
                visited,
                [f'{node_by_id[p["id"]]["label"]}(h={p["h"]})' for p in pq],
                f'Picked {node_by_id[item["id"]]["label"]} with lowest h(n)={item["h"]}',
            )
        return pack(False, "noPath", None, [], None)

    # A* Search: f(n) = g(n) + h(n)
    closed = set()
    best_g = {start_id: 0}
    h0 = heuristic(start_id, goal_id, node_by_id)
    open_list = [{"id": start_id, "path": [start_id], "g": 0, "h": h0, "f": h0}]
    while open_list:
        max_frontier = max(max_frontier, len(open_list))
        open_list.sort(key=lambda p: (p["f"], p["h"]))
        item = open_list.pop(0)
        if item["id"] in closed:
            continue
        closed.add(item["id"])
        expanded += 1
        if item["id"] == goal_id:
            push(
                item["id"],
                closed,
                [f'{node_by_id[p["id"]]["label"]}(f={p["f"]})' for p in open_list],
                f'Optimal Attack Path found! Total cost f=g={item["g"]}',
                item["path"],
            )
            return pack(True, "optimal", None, item["path"], item["g"])
        for edge in neighbors(item["id"]):
            tentative_g = item["g"] + edge["cost"]
            if edge["to"] not in closed and (edge["to"] not in best_g or tentative_g < best_g[edge["to"]]):
                best_g[edge["to"]] = tentative_g
                h_val = heuristic(edge["to"], goal_id, node_by_id)
                open_list.append(
                    {
                        "id": edge["to"],
                        "path": item["path"] + [edge["to"]],
                        "g": tentative_g,
                        "h": h_val,
                        "f": tentative_g + h_val,
                    }
                )
        max_frontier = max(max_frontier, len(open_list))
        push(
            item["id"],
            closed,
            [f'{node_by_id[p["id"]]["label"]}(f={p["f"]})' for p in open_list],
            f'Expanded {node_by_id[item["id"]]["label"]}: f={item["f"]} (g={item["g"]} + h={item["h"]})',
        )
    return pack(False, "noPath", None, [], None)
