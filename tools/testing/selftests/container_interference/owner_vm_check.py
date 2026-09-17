#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Check mechanism evidence, separately from fleet/process success or S6 cost."""
import argparse
import importlib.util
import json
import re
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "owner", Path(__file__).resolve().parents[3]/"container_interference/owner_report.py")
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)


def check(path, preempt):
    sections, section = {}, "boot"
    for line in Path(path).read_text().splitlines():
        if line.startswith("CIS_FILE "):
            section = line.split(" ", 1)[1]
        else:
            sections.setdefault(section, []).append(line)
    cases = {}
    for lines in sections.values():
        start = next((s for s in lines if s.startswith("CIS_FLEET_BEGIN ")), None)
        if not start:
            continue
        f = owner.fields(start)
        name = re.search(r"workload=(\S+)", start).group(1)
        records = [json.loads(s) for s in sections.get(
            f'/tmp/observer-{f["observer_pid"]}.jsonl', []) if s.startswith('{"version":')]
        report = owner.analyze(records)
        truth = [owner.fields(s) for s in lines if s.startswith("CIS_TRUTH ")]
        dentries = [owner.fields(s) for s in lines if s.startswith("CIS_DENTRY ")]
        objects = {q["object"] for q in truth+dentries}
        edges = [e for e in report["edges"] if int(e["object"], 16) in objects]
        wrong = 0
        for e in edges:
            if truth and not any(q["object"] == int(e["object"], 16) and
                q["host_tid"] == (e["holder"][2] & 0xffffffff) and
                q["cgroup_id"] == e["holder"][0] and
                min(q["released_ns"], e["end_ns"]) > max(q["acquired_ns"], e["begin_ns"])
                for q in truth):
                wrong += 1
        resets = [owner.fields(s)["time_ns"] for s in lines if s.startswith("CIS_RESET ")]
        candidates = [r for r in records if r["kind"] == "FAST_LOCK_CANDIDATE" and r["time_ns"] >= f["start_ns"]]
        cases[name] = {
            "fleet_pass": "CIS_FLEET_END result=PASS" in lines,
            "objects": len(objects), "e2": sum(e["level"] == "E2" for e in edges),
            "edges": len(edges), "wrong_holder_intersections": wrong,
            "crossed_resets": sum(e["begin_ns"] < t < e["end_ns"] for e in edges for t in resets),
            "directions": len({(e["holder"][0], e["waiter"][0]) for e in edges}),
            "preempted": sum(s["reason"] == "preempted" for e in edges for s in e["holder_offcpu"]),
            "reset_count": len(resets), "loss": report["loss_or_recursion_gap"],
            "prefix_limits": report["bounded_prefix_limits"],
            "lock_candidate_ms": (candidates[0]["time_ns"]-f["start_ns"])/1e6 if candidates else None,
            "real_dentry_slowpaths": sum(q["slowpaths"] for q in dentries if q.get("real_dentry")),
        }
    failures = []
    for name in ("bench", "cpu-compete", "quota"):
        if name not in cases or not cases[name]["fleet_pass"]:
            failures.append(name+": surrounding fast-warning control failed")
    required = ("fixture-shared", "fixture-private", "fixture-reuse",
                "dentry-shared", "dentry-private", "dentry-auto")
    for name in required + (("fixture-preempt",) if preempt else ()):
        c = cases.get(name)
        if not c or not c["fleet_pass"] or c["loss"] or c["wrong_holder_intersections"] or c["crossed_resets"]:
            failures.append(name+": missing, failed, contradictory or incomplete evidence")
            continue
        if name.endswith("private"):
            if c["objects"] != 2 or c["edges"]:
                failures.append(name+": private objects were merged")
        elif not c["e2"] or c["directions"] != 2:
            failures.append(name+": no verified bidirectional ownership")
        if name == "fixture-reuse" and c["reset_count"] < 2:
            failures.append(name+": reuse not exercised")
        if name == "fixture-preempt" and not c["preempted"]:
            failures.append(name+": actual busy-holder preemption not observed")
        if name.startswith("dentry-") and not name.endswith("private") and not c["real_dentry_slowpaths"]:
            failures.append(name+": no actual dentry fallback")
        if name == "dentry-auto" and c["lock_candidate_ms"] is None:
            failures.append(name+": automatic candidate not observed")
    return {"log": path, "require_preempt": preempt, "cases": cases,
            "failures": failures, "status": "FAIL" if failures else "PASS",
            "scope": "bounded fixture mechanism checks only; not full recall, production attribution or S6 cost acceptance"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("log")
    parser.add_argument("--require-preempt", action="store_true")
    args = parser.parse_args()
    result = check(args.log, args.require_preempt)
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(result["failures"]))
