#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Conservative, timestamp-ordered joins, never snapshot-to-duration inference."""
import argparse
import json
import re
from collections import defaultdict

RESOURCES = {1: 'mutex', 2: 'lockref', 3: 'files_struct_lock', 4: 'slub_node_list_lock'}


def fields(detail):
    return {k: int(v, 0) for k, v in re.findall(r"(\w+)=(-?0x[0-9a-fA-F]+|-?\d+)", detail)}


def actor(e):
    return tuple(e.get(k, 0) for k in ("actor_id", "actor_generation", "actor_tid", "actor_start"))


def analyze(records):
    sessions = {r.get('session_id', 0) for r in records if r.get('kind') == 'OWNER'}
    if len(sessions) > 1:
        raise ValueError('owner records from distinct sessions must not be joined')
    groups = defaultdict(list)
    stacks, symbols = {}, {}
    unsupported_resources = 0
    for r in records:
        if r.get("kind") not in ("stack", "stack_symbols"):
            continue
        detail = r.get("detail", "")
        ident = fields(detail).get("stack_id", -1)
        if r["kind"] == "stack" and " ips=" in detail:
            stacks[ident] = detail.split(" ips=", 1)[1].split(",")
        elif " leaf_to_root=" in detail:
            symbols[ident] = detail.split(" leaf_to_root=", 1)[1].split(">")
    loss = any(r.get("kind") in ("buffer_loss", "sample_schema_error", "owner_gap") for r in records)
    loss |= any((r.get("kind") == "coverage" and fields(r.get("detail", "")).get("lost", 0)) or
                (r.get("kind") == "terminal_coverage" and any(fields(r.get("detail", "")).values())) or
                (r.get("kind") == "final_quality" and fields(r.get("detail", "")).get("drops", 0)) for r in records)
    for r in records:
        if r.get("kind") != "OWNER":
            continue
        e = fields(r["detail"])
        if e.get('resource') not in RESOURCES:
            unsupported_resources += 1
            continue
        loss |= bool(e.get("skipped", 0))
        groups[(e["resource"], e["object"], e["epoch"])].append(e)
    edges, incomplete, snapshots, resets, aborted = [], 0, 0, 0, 0
    cache_identity_errors = 0
    legacy = any(e.get("protocol", 1) != 2 for es in groups.values() for e in es)
    for key, events in groups.items():
        cache = None
        if key[0] == 4:
            # Scheduler records do not carry a cache address.
            caches = {e.get('cache', 0) for e in events if e['phase'] not in (9, 10)}
            if len(caches) != 1 or 0 in caches:
                cache_identity_errors += 1
                continue
            cache = hex(next(iter(caches)))
        # Duplicate cached acquires are the same observation, not new ownership.
        unique = {(e["sample_time_ns"], e["phase"], actor(e)): e for e in events}
        events = sorted(unique.values(), key=lambda e: (e["sample_time_ns"], e["phase"]))
        holding = None
        waits, holds, finished = {}, [], []
        off = {}
        off_spans = defaultdict(list)
        for e in events:
            who, t, phase = actor(e), e["sample_time_ns"], e["phase"]
            if phase in (1, 7, 8, 11):
                resets += phase in (1, 8)
                incomplete += len(waits) + bool(holding)
                waits.clear()
                holding = None
                off.clear()
            elif phase == 2:
                snapshots += bool(e.get("holder_tid"))
                if who in waits:
                    incomplete += 1
                waits[who] = e
            elif phase in (3, 12):
                if who in waits:
                    w = waits.pop(who)
                    if (w.get("attempt_ns") and w["attempt_ns"] == e.get("attempt_ns")
                            and w.get("protocol") == e.get("protocol") == 2):
                        finished.append((who, w["sample_time_ns"], t, w.get("stack_id", -1),
                                         w["attempt_ns"], "aborted" if phase == 12 else "acquired",
                                         e.get("result", 0)))
                    else:
                        incomplete += 1
                if phase == 12:
                    aborted += 1
                    continue
                if holding is not None:
                    incomplete += 1
                holding = (who, t)
            elif phase == 4:
                if holding and holding[0] == who and holding[1] <= t:
                    holds.append((who, holding[1], t))
                    if who in off:
                        start, flags = off.pop(who)
                        off_spans[who].append((start, t, flags))
                else:
                    incomplete += 1
                holding = None
            elif phase == 9:
                if holding and holding[0] == who:
                    if who in off:
                        incomplete += 1
                    off[who] = (t, e.get("flags", 0))
            elif phase == 10 and who in off:
                start, flags = off.pop(who)
                off_spans[who].append((start, t, flags))
            # RELEASE_END is deliberately not a hold endpoint: handoff may precede it.
        incomplete += len(waits) + bool(holding)
        for waiter, begin, end, stack, attempt, outcome, result in finished:
            for holder, acquired, released in holds:
                lo, hi = max(begin, acquired), min(end, released)
                if hi <= lo or waiter == holder or not all(waiter) or not all(holder):
                    continue
                sched = []
                for out, back, flags in off_spans[holder]:
                    left, right = max(lo, out), min(hi, back)
                    if right > left:
                        sched.append({"begin_ns": left, "end_ns": right, "ns": right-left,
                                      "reason": "preempted" if flags & 1 else "sleeping" if flags & 2 else "runnable_deschedule"})
                edges.append({"resource": RESOURCES[key[0]], "object": hex(key[1]),
                              "epoch": key[2], "waiter": waiter, "holder": holder,
                              "relation": "container_internal" if waiter[:2] == holder[:2] else "cross_container",
                              "relation_type": "holder_waiter", "causal": False,
                              "wait_metric": "acquisition_attempt_wall_interval" if key[0] in (3, 4) else "observed_wait_wall_interval",
                              "cache_address": cache,
                              "process_scope": ("UNKNOWN" if not (waiter[2] >> 32) or not (holder[2] >> 32)
                                                else "same_tgid" if (waiter[2] >> 32) == (holder[2] >> 32)
                                                else "different_tgid"),
                              "attempt_ns": attempt, "outcome": outcome, "result": result,
                              "begin_ns": lo, "end_ns": hi, "overlap_ns": hi-lo,
                              "wait_begin_ns": begin, "wait_end_ns": end, "stack_id": stack,
                              "waiter_stack_ips": stacks.get(stack, []),
                              "waiter_stack_leaf_to_root": symbols.get(stack, []),
                              "holder_offcpu": sched,
                              "offcpu_coverage": "observed lower bound; nested held objects or map eviction may leave gaps",
                              "level": "INCOMPLETE" if loss or legacy else "E2",
                              "meaning": ("FD acquisition attempt overlaps observed ownership; may include pre-lock scheduling and instrumentation"
                                          if key[0] == 3 else
                                          "SLUB node-lock acquisition attempt overlaps observed inner ownership; not pure spin cycles, full holder history or measured causal delay"
                                          if key[0] == 4 else
                                          "observed exclusive ownership overlaps observed wait; not total wait or CPU burn")})
    return {"version": 2, "edges": edges, "incomplete_intervals": incomplete, "point_snapshots": snapshots,
            "aborted_attempts": aborted, "legacy_protocol": legacy,
            "bounded_prefix_limits": sum(e["phase"]==11 for events in groups.values() for e in events),
            "lifecycle_boundaries": resets, "loss_or_recursion_gap": loss,
            "unsupported_resource_events": unsupported_resources,
            "cache_identity_errors": cache_identity_errors,
            "scope": "explicit non-RT mutex, lockref fallback, configured files_struct and boot-selected SLUB node-lock adapters; missing intervals unknown"}


def read_records(path):
    records = []
    for line in open(path):
        if line.startswith('{"version":'):
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append({"kind": "sample_schema_error"})
    return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("log")
    args = parser.parse_args()
    print(json.dumps(analyze(read_records(args.log)), indent=2))
