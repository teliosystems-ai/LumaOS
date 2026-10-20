#!/usr/bin/env python3
"""Read-only, bounded G3 held-out quality evidence ingestion; never runs a task.

All input digests must be independently supplied by the operator. Digest joins
authenticate neither a human reviewer nor installed execution. No input text,
receipt, model answer or aggregate grants authority or closes a release gate.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

MAX_DOCUMENT = 4 * 1024 * 1024
MAX_ARTIFACT = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_ATTEMPTS = 8
TASKS = 500
TUPLE_KEYS = {"source_manifest_sha256", "image_manifest_sha256", "model_sha256",
              "runtime_sha256", "machine_id_sha256"}
HEX = re.compile(r"[0-9a-f]{64}")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}")


class Invalid(ValueError):
    """Incomplete, changed, unjoined or unsupported evidence."""


def require(condition, message):
    if not condition:
        raise Invalid(message)


def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys), "closed object fields differ")
    return value


def integer(value, minimum=0, maximum=2**63 - 1):
    require(type(value) is int and minimum <= value <= maximum, "bounded integer required")
    return value


def text(value, maximum=512, empty=False):
    require(type(value) is str and (empty or bool(value)) and len(value.encode("utf-8")) <= maximum
            and all(ord(c) >= 32 and ord(c) != 127 for c in value), "bounded visible text required")
    return value


def digest(value):
    require(type(value) is str and HEX.fullmatch(value) is not None, "lowercase SHA256 required")
    return value


def identifier(value):
    require(type(value) is str and ID.fullmatch(value) is not None, "exact identifier required")
    return value


def relative_path(value):
    path = text(value, 240)
    require(not path.startswith("/") and "\\" not in path and ":" not in path
            and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", part)
                    and part not in (".", "..") for part in path.split("/")),
            "canonical relative evidence path required")
    return path


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha(value):
    return hashlib.sha256(value).hexdigest()


def strict_json(data, *, exact_numbers=False):
    require(type(data) is bytes and 0 < len(data) <= MAX_DOCUMENT, "JSON byte bound exceeded")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    def no_constant(_):
        raise Invalid("nonfinite JSON number")
    def exact_float(token):
        require(len(token) <= 96, "JSON numeric oracle literal bound exceeded")
        try:
            number = Decimal(token)
            require(number.is_finite() and abs(number.adjusted()) <= 10000,
                    "JSON numeric oracle exponent bound exceeded")
            return number
        except InvalidOperation as error:
            raise Invalid("invalid exact JSON numeric literal") from error
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=no_constant,
                           parse_float=exact_float if exact_numbers else float)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Invalid("invalid strict JSON") from error
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        require(depth <= 24 and nodes <= 150000, "JSON structure bound exceeded")
        if type(item) is float:
            require(math.isfinite(item), "nonfinite JSON number")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value


def same_json(left, right):
    # JSON true and1 are not interchangeable; neither are1 and1.0.
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(same_json(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(same_json(a, b) for a, b in zip(left, right))
    return left == right


def timestamp(value):
    require(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value),
            "whole-second UTC timestamp required")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise Invalid("invalid UTC timestamp") from error


class Files:
    """Single-link regular files, no symlink/reparse ancestors or path aliases.

    Immutable bytes are retained and a final re-observation detects changes.
    This is evidence handling, not a substitute for native custody/authorization.
    """
    def __init__(self, root):
        self.root = Path(os.path.abspath(root))
        self.total = 0
        self.seen = {}
        self._ancestors(self.root, directory=True)

    @staticmethod
    def _ancestors(path, directory=False):
        for parent in reversed(path.parents):
            value = parent.lstat()
            require(stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode)
                    and not getattr(value, "st_file_attributes", 0) & 0x400,
                    "alias/reparse ancestor refused")
        value = path.lstat()
        require(not stat.S_ISLNK(value.st_mode)
                and not getattr(value, "st_file_attributes", 0) & 0x400, "file alias refused")
        if directory:
            require(stat.S_ISDIR(value.st_mode), "directory required")

    @staticmethod
    def _identity(value):
        return (value.st_dev, value.st_ino, value.st_size, value.st_nlink,
                value.st_mtime_ns, value.st_ctime_ns, value.st_mode)

    def read(self, pin, maximum=MAX_ARTIFACT):
        closed(pin, {"path", "bytes", "sha256"})
        path = relative_path(pin["path"])
        size = integer(pin["bytes"], 0, maximum)
        expected = digest(pin["sha256"])
        target = self.root.joinpath(*path.split("/"))
        self._ancestors(target)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(target, flags)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == size,
                    "single-link bounded regular evidence required")
            pieces = []
            count = 0
            while count <= size:
                block = os.read(fd, min(65536, size - count + 1))
                if not block:
                    break
                pieces.append(block)
                count += len(block)
            data = b"".join(pieces)
            require(self._identity(before) == self._identity(os.fstat(fd)), "evidence changed while read")
        finally:
            os.close(fd)
        self._ancestors(target)
        require(self._identity(before) == self._identity(target.lstat())
                and len(data) == size and sha(data) == expected, "evidence digest/identity differs")
        observation = (self._identity(before), expected)
        if path in self.seen:
            require(self.seen[path] == observation, "conflicting evidence pin")
        else:
            self.total += size
            require(self.total <= MAX_TOTAL and len(self.seen) < 20000, "total evidence budget exceeded")
            self.seen[path] = observation
        return data

    def finish(self):
        for path, (identity, expected) in list(self.seen.items()):
            self.read({"path": path, "bytes": identity[2], "sha256": expected})


def document(files, path, expected):
    path = relative_path(path)
    digest(expected)
    target = files.root.joinpath(*path.split("/"))
    value = target.lstat()
    pin = {"path": path, "bytes": value.st_size, "sha256": digest(expected)}
    return strict_json(files.read(pin, MAX_DOCUMENT))


def projection(files, entries, maximum=MAX_ARTIFACT, *, retain=True):
    require(type(entries) is list and len(entries) <= 16, "bounded artifact/input set required")
    previous = ""
    result = {}
    for item in entries:
        closed(item, {"name", "file"})
        name = identifier(item["name"])
        require(previous < name, "artifact/input names must be unique and sorted")
        previous = name
        data = files.read(item["file"], maximum)
        if retain:
            result[name] = data
    return sha(canonical(entries)), result


def validate_corpus(files, corpus):
    closed(corpus, {"schema_version", "corpus_id", "classification", "tasks"})
    require(type(corpus["schema_version"]) is int and corpus["schema_version"] == 1
            and corpus["classification"] == "external-held-out", "held-out corpus declaration required")
    identifier(corpus["corpus_id"])
    tasks = corpus["tasks"]
    require(type(tasks) is list and len(tasks) == TASKS, "exactly500 tasks required")
    previous = ""
    by_id = {}
    task_identities = set()
    validated_oracles = set()
    for task in tasks:
        closed(task, {"task_id", "expected", "inputs", "oracle"})
        name = identifier(task["task_id"])
        require(previous < name, "500 unique sorted task IDs required")
        previous = name
        require(task["expected"] in ("complete", "refuse"), "explicit expected task disposition required")
        input_digest, _ = projection(files, task["inputs"], retain=False)
        require(bool(task["inputs"]), "retained task input required")
        oracle = task["oracle"]
        require(type(oracle) is dict, "oracle required")
        kind = oracle.get("kind")
        if kind == "must-refuse":
            closed(oracle, {"kind"})
            require(task["expected"] == "refuse", "refusal oracle disposition differs")
            oracle_pin = None
        elif kind == "human-rubric":
            closed(oracle, {"kind", "rubric"})
            oracle_pin = oracle["rubric"]
            require(task["expected"] == "complete", "human oracle only for permitted tasks")
        else:
            closed(oracle, {"kind", "artifact", "expected"})
            require(kind in ("bytes-exact", "json-exact", "decimal-csv-exact")
                    and task["expected"] == "complete", "unsupported deterministic oracle")
            identifier(oracle["artifact"])
            oracle_pin = oracle["expected"]
        if oracle_pin is not None:
            # Deduplicate validation by exact kind/pin, retaining metadata only.
            # A shared16MiB oracle must not become500 retained16MiB copies.
            oracle_key = (kind, sha(canonical(oracle_pin)))
            if oracle_key not in validated_oracles:
                oracle_bytes = files.read(oracle_pin, 65536 if kind == "human-rubric" else MAX_ARTIFACT)
                if kind == "human-rubric":
                    text(oracle_bytes.decode("utf-8"), 65536)
                elif kind == "json-exact":
                    strict_json(oracle_bytes, exact_numbers=True)
                elif kind == "decimal-csv-exact":
                    decimal_csv(oracle_bytes)
                validated_oracles.add(oracle_key)
                del oracle_bytes
        # A renamed task or copied oracle file cannot pad the denominator.
        oracle_identity = {"kind": kind}
        if oracle_pin is not None:
            oracle_identity.update(bytes=oracle_pin["bytes"], sha256=oracle_pin["sha256"])
        if "artifact" in oracle:
            oracle_identity["artifact"] = oracle["artifact"]
        identity = sha(canonical({"inputs": [{"name": item["name"], "bytes": item["file"]["bytes"],
                    "sha256": item["file"]["sha256"]} for item in task["inputs"]],
                    "expected": task["expected"], "oracle": oracle_identity}))
        require(identity not in task_identities, "duplicate task content under another ID")
        task_identities.add(identity)
        by_id[name] = (task, input_digest, oracle_identity)
    return by_id


def decimal_csv(data):
    require(len(data) <= MAX_DOCUMENT, "numeric CSV byte bound exceeded")
    try:
        rows = []
        cells = 0
        for row in csv.reader(io.StringIO(data.decode("utf-8"), newline=""), strict=True):
            cells += len(row)
            require(len(rows) < 10000 and 0 < len(row) <= 256 and cells <= 100000,
                    "numeric CSV structure bound exceeded")
            rows.append(row)
    except (UnicodeError, csv.Error) as error:
        raise Invalid("invalid numeric CSV") from error
    require(0 < len(rows) <= 10000 and 0 < len(rows[0]) <= 256
            and sum(map(len, rows)) <= 100000
            and all(len(row) == len(rows[0]) for row in rows), "bounded rectangular numeric CSV required")
    result = []
    for row in rows:
        converted = []
        for cell in row:
            require(len(cell) <= 80 and re.fullmatch(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]{1,18})?", cell),
                    "fixed decimal literal required; formulas/nonfinite/exponents refused")
            converted.append(Decimal(cell))
        result.append(converted)
    return result


def observation(files, pin, run_id, task_id, sequence, context_sha256, duration_ns):
    value = strict_json(files.read(pin, 65536))
    closed(value, {"schema_version", "run_id", "task_id", "attempt", "context_sha256", "clock",
                   "started_ns", "finished_ns", "ack_ns", "first_result_ns", "cancel_requested_ns",
                   "cancel_ack_ns", "peak_memory_bytes", "peak_memory_evidence", "energy_evidence"})
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["run_id"] == run_id and value["task_id"] == task_id
            and type(value["attempt"]) is int and value["attempt"] == sequence
            and value["context_sha256"] == context_sha256 and value["clock"] == "run-relative-monotonic-ns",
            "measurement run/task/context join differs")
    start = integer(value["started_ns"], 0, duration_ns)
    end = integer(value["finished_ns"], start + 1, duration_ns)
    ack = integer(value["ack_ns"], start, end)
    first = value["first_result_ns"]
    if first is not None:
        integer(first, ack, end)
    cancel, stopped = value["cancel_requested_ns"], value["cancel_ack_ns"]
    require((cancel is None) == (stopped is None), "incomplete cancellation observation")
    if cancel is not None:
        integer(cancel, ack, end)
        integer(stopped, cancel, end)
    memory = integer(value["peak_memory_bytes"], 1)
    memory_raw = files.read(value["peak_memory_evidence"], 64)
    require(memory_raw == str(memory).encode() + b"\n", "peak-memory observation differs from retained counter")
    energy = strict_json(files.read(value["energy_evidence"], 4096))
    closed(energy, {"schema_version", "run_id", "task_id", "attempt", "context_sha256", "method", "domain",
                    "started_ns", "finished_ns", "start_microjoules", "end_microjoules"})
    require(type(energy["schema_version"]) is int and energy["schema_version"] == 1
            and energy["run_id"] == run_id and energy["task_id"] == task_id
            and type(energy["attempt"]) is int and energy["attempt"] == sequence
            and energy["context_sha256"] == context_sha256
            and type(energy["started_ns"]) is int and energy["started_ns"] == start
            and type(energy["finished_ns"]) is int and energy["finished_ns"] == end
            and energy["method"] in ("kernel-counter", "external-meter"), "energy observation join differs")
    domain = text(energy["domain"], 128)
    initial = integer(energy["start_microjoules"])
    final = integer(energy["end_microjoules"], initial)
    return {"start_ns": start, "end_ns": end, "elapsed_ns": end - start, "input_ack_ns": ack - start,
            "first_result_ns": None if first is None else first - start,
            "cancel_ack_ns": None if cancel is None else stopped - cancel, "peak_memory_bytes": memory,
            "energy_microjoules": final - initial, "energy_domain": domain, "energy_method": energy["method"]}


def percentile(values, percent):
    return None if not values else sorted(values)[math.ceil(percent * len(values) / 100) - 1]


def evaluate(files, corpus_path, corpus_sha256, run_path, run_sha256, manifest_path, manifest_sha256,
             adjudications_path, adjudications_sha256, *, now=None, max_age_seconds=604800):
    integer(max_age_seconds, 1, 604800)
    corpus = document(files, corpus_path, corpus_sha256)
    tasks = validate_corpus(files, corpus)
    manifest = document(files, manifest_path, manifest_sha256)
    closed(manifest, {"schema_version", "run_id", "profile", "corpus_sha256", "tuple", "started_utc", "finished_utc"})
    require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
            and manifest["corpus_sha256"] == corpus_sha256 and manifest["profile"] in ("compact", "mainstream"),
            "current manifest/corpus/profile differs")
    run_id = identifier(manifest["run_id"])
    closed(manifest["tuple"], TUPLE_KEYS)
    for value in manifest["tuple"].values():
        digest(value)
    started, finished = timestamp(manifest["started_utc"]), timestamp(manifest["finished_utc"])
    current = now or datetime.now(timezone.utc)
    require(current.tzinfo is not None and started < finished <= current
            and (current - finished).total_seconds() <= max_age_seconds
            and (finished - started).total_seconds() <= 86400, "stale/future/unbounded run interval")
    duration_ns = int((finished - started).total_seconds()) * 1000000000
    context = {"run_id": run_id, "corpus_sha256": corpus_sha256, "current_manifest_sha256": manifest_sha256,
               "tuple": manifest["tuple"]}
    context_digest = sha(canonical(context))
    run = document(files, run_path, run_sha256)
    closed(run, {"schema_version", "context", "observations"})
    require(type(run["schema_version"]) is int and run["schema_version"] == 1
            and same_json(run["context"], context), "run does not join independently pinned current manifest")
    adjudications = document(files, adjudications_path, adjudications_sha256)
    closed(adjudications, {"schema_version", "run_sha256", "context_sha256", "origin", "decisions"})
    require(type(adjudications["schema_version"]) is int and adjudications["schema_version"] == 1
            and adjudications["run_sha256"] == run_sha256 and adjudications["context_sha256"] == context_digest
            and adjudications["origin"] == "external-human", "external adjudication does not join exact run")
    require(type(adjudications["decisions"]) is list and len(adjudications["decisions"]) <= TASKS * MAX_ATTEMPTS,
            "adjudication count bound exceeded")
    decisions = {}
    for decision in adjudications["decisions"]:
        closed(decision, {"task_id", "attempt", "artifact_set_sha256", "rubric_sha256", "reviewer", "decision", "reason"})
        key = (identifier(decision["task_id"]), integer(decision["attempt"], 1, MAX_ATTEMPTS))
        digest(decision["artifact_set_sha256"])
        digest(decision["rubric_sha256"])
        text(decision["reviewer"], 128)
        text(decision["reason"])
        require(key not in decisions and decision["decision"] in ("pass", "fail"), "duplicate/invalid adjudication")
        decisions[key] = decision
    observations = run["observations"]
    require(type(observations) is list and len(observations) == TASKS, "complete500task observations required")
    task_results, measurements = [], []
    expected_ids = list(tasks)
    last_end = 0
    for index, entry in enumerate(observations):
        closed(entry, {"task_id", "input_set_sha256", "attempts"})
        task_id = entry["task_id"]
        require(task_id == expected_ids[index], "observations must exactly match500 sorted corpus IDs")
        task, input_digest, oracle_identity = tasks[task_id]
        kind = task["oracle"]["kind"]
        oracle_bytes = None if kind == "must-refuse" else files.read(
            task["oracle"]["rubric" if kind == "human-rubric" else "expected"],
            65536 if kind == "human-rubric" else MAX_ARTIFACT)
        require(entry["input_set_sha256"] == input_digest, "observed task input digest differs")
        attempts = entry["attempts"]
        require(type(attempts) is list and 1 <= len(attempts) <= MAX_ATTEMPTS, "bounded nonempty attempts required")
        outcomes = []
        for sequence, attempt in enumerate(attempts, 1):
            # Never retain the preceding attempt's output dictionary while
            # constructing this one (shared pins still consume real memory).
            artifacts = {}
            actual = None
            closed(attempt, {"attempt", "status", "reason", "artifacts", "receipt", "measurement"})
            require(type(attempt["attempt"]) is int and attempt["attempt"] == sequence
                    and attempt["status"] in ("completed", "refused", "failed", "cancelled"), "attempt sequence/status differs")
            text(attempt["reason"], empty=attempt["status"] == "completed")
            artifact_digest, artifacts = projection(files, attempt["artifacts"])
            receipt = strict_json(files.read(attempt["receipt"], 65536))
            closed(receipt, {"schema_version", "run_id", "task_id", "attempt", "context_sha256", "input_set_sha256",
                            "artifact_set_sha256", "status", "authority_returned"})
            require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
                    and receipt["run_id"] == run_id and receipt["task_id"] == task_id
                    and type(receipt["attempt"]) is int and receipt["attempt"] == sequence
                    and receipt["context_sha256"] == context_digest and receipt["input_set_sha256"] == input_digest
                    and receipt["artifact_set_sha256"] == artifact_digest and receipt["status"] == attempt["status"]
                    and receipt["authority_returned"] is False, "retained receipt join differs or claims authority")
            metric = observation(files, attempt["measurement"], run_id, task_id, sequence, context_digest, duration_ns)
            require(metric["start_ns"] >= last_end, "serialized QA observations overlap or move backwards")
            last_end = metric["end_ns"]
            require((metric["cancel_ack_ns"] is not None) == (attempt["status"] == "cancelled"), "cancellation/status differs")
            if attempt["status"] == "completed":
                require(bool(artifacts) and metric["first_result_ns"] is not None, "completed task needs retained artifacts and first-result observation")
            metric.update(task_id=task_id, attempt=sequence, status=attempt["status"])
            measurements.append(metric)
            passed = False
            if kind == "must-refuse":
                passed = attempt["status"] == "refused" and not artifacts
            elif attempt["status"] == "completed":
                if kind == "human-rubric":
                    key = (task_id, sequence)
                    require(key in decisions, "missing external human adjudication")
                    decision = decisions.pop(key)
                    require(decision["artifact_set_sha256"] == artifact_digest
                            and decision["rubric_sha256"] == oracle_identity["sha256"], "adjudication rubric/artifacts differ")
                    passed = decision["decision"] == "pass"
                else:
                    name = task["oracle"]["artifact"]
                    require(name in artifacts, "deterministic oracle artifact missing")
                    actual = artifacts[name]
                    if kind == "bytes-exact":
                        passed = actual == oracle_bytes
                    else:
                        # Malformed OUTPUT is an observed task failure, not a
                        # malformed evidence envelope or an aborted benchmark.
                        # Expected oracle validation above remains fail-closed.
                        try:
                            if kind == "json-exact":
                                passed = same_json(strict_json(actual, exact_numbers=True), strict_json(oracle_bytes, exact_numbers=True))
                            else:
                                passed = decimal_csv(actual) == decimal_csv(oracle_bytes)
                        except (Invalid, UnicodeError):
                            passed = False
            outcomes.append({"attempt": sequence, "status": attempt["status"], "oracle_passed": passed,
                             "false_refusal": attempt["status"] == "refused" and task["expected"] == "complete"})
        task_results.append({"task_id": task_id, "attempts": outcomes, "initial_success": outcomes[0]["oracle_passed"],
                             "final_success": outcomes[-1]["oracle_passed"],
                             "repaired": len(outcomes) > 1 and not outcomes[0]["oracle_passed"] and outcomes[-1]["oracle_passed"]})
        artifacts.clear()
        actual = None
        oracle_bytes = None
    require(not decisions, "unmatched/excess human adjudication")
    files.finish()
    initial = sum(item["initial_success"] for item in task_results)
    final = sum(item["final_success"] for item in task_results)
    all_outcomes = [attempt for task in task_results for attempt in task["attempts"]]
    threshold = 425 if manifest["profile"] == "compact" else 450
    energy_totals = {}
    for metric in measurements:
        key = metric["energy_method"] + ":" + metric["energy_domain"]
        energy_totals[key] = integer(energy_totals.get(key, 0) + metric["energy_microjoules"])
    return {"schema_version": 1, "scope": "read-only-operator-pinned-evidence-ingestion", "context": context,
            "run_sha256": run_sha256, "adjudications_sha256": adjudications_sha256,
            "tasks": TASKS, "attempts": len(measurements), "initial_successes": initial, "final_successes": final,
            "initial_success_basis_points": initial * 20, "final_success_basis_points": final * 20,
            "repaired_tasks": sum(item["repaired"] for item in task_results),
            "retried_tasks": sum(len(item["attempts"]) > 1 for item in task_results),
            "false_refusal_attempts": sum(item["false_refusal"] for item in all_outcomes),
            "status_counts": {status: sum(item["status"] == status for item in all_outcomes)
                              for status in ("completed", "refused", "failed", "cancelled")},
            "oracle_failed_attempts": sum(not item["oracle_passed"] for item in all_outcomes),
            "q10": {"required_successes": threshold, "denominator": TASKS,
                    "initial_threshold_met": initial >= threshold, "final_threshold_met": final >= threshold,
                    "repair_policy_not_inferred": True, "gate_closed": False},
            "metrics": {"p95_elapsed_ns": percentile([m["elapsed_ns"] for m in measurements], 95),
                        "p95_input_ack_ns": percentile([m["input_ack_ns"] for m in measurements], 95),
                        "p95_first_result_ns": percentile([m["first_result_ns"] for m in measurements if m["first_result_ns"] is not None], 95),
                        "p95_cancel_ack_ns": percentile([m["cancel_ack_ns"] for m in measurements if m["cancel_ack_ns"] is not None], 95),
                        "maximum_peak_memory_bytes": max(m["peak_memory_bytes"] for m in measurements),
                        "p95_peak_memory_bytes": percentile([m["peak_memory_bytes"] for m in measurements], 95),
                        "energy_microjoules_by_method_and_domain": energy_totals,
                        "percentile_method": "nearest-rank", "all_attempts_included": True},
            "task_results": task_results, "measurements": measurements,
            "verified_evidence_files": len(files.seen), "verified_evidence_bytes": files.total,
            "claims": {"held_out_secrecy_verified": False, "human_reviewer_identity_authenticated": False,
                       "measurement_origin_authenticated": False, "installed_authorization_qualified": False,
                       "tuple_payloads_fully_rehashed": False, "native_receipt_semantics_authenticated": False,
                       "native_hardware_qualified": False, "other_quality_requirements_qualified": False,
                       "production_qualified": False, "gate_closing": False}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-corpus", help="verify a pinned external500task corpus before execution")
    validate.add_argument("--evidence-root", required=True, type=Path)
    validate.add_argument("--corpus", required=True)
    validate.add_argument("--corpus-sha256", required=True)
    aggregate = commands.add_parser("aggregate", help="join a complete externally executed run; does not execute tasks")
    aggregate.add_argument("--evidence-root", required=True, type=Path)
    for name in ("corpus", "run", "current-manifest", "adjudications"):
        aggregate.add_argument("--" + name, required=True)
        aggregate.add_argument("--" + name + "-sha256", required=True)
    aggregate.add_argument("--max-age-seconds", type=int, default=604800)
    args = parser.parse_args(argv)
    try:
        files = Files(args.evidence_root)
        if args.command == "validate-corpus":
            corpus = document(files, args.corpus, args.corpus_sha256)
            tasks = validate_corpus(files, corpus)
            files.finish()
            result = {"schema_version": 1, "scope": "operator-pinned-corpus-structure-and-byte-validation",
                      "corpus_sha256": args.corpus_sha256, "tasks": len(tasks), "held_out_secrecy_verified": False,
                      "verified_evidence_files": len(files.seen), "verified_evidence_bytes": files.total,
                      "task_execution_performed": False, "authority_returned": False, "gate_closing": False}
        else:
            result = evaluate(files, args.corpus, args.corpus_sha256, args.run, args.run_sha256,
                              args.current_manifest, args.current_manifest_sha256, args.adjudications,
                              args.adjudications_sha256, max_age_seconds=args.max_age_seconds)
        sys.stdout.buffer.write(canonical(result) + b"\n")
        return 0
    except (Invalid, OSError, UnicodeError, OverflowError, RecursionError, csv.Error) as error:
        print("G3 quality evidence refused: " + ascii(str(error)), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
