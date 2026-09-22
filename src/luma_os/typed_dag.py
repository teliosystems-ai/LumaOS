"""Deterministic typed-DAG execution and restart checkpoints.

The executor is deliberately small and dependency free.  It validates graph
shape and value types before invoking a node, evaluates policy immediately
before each node, and publishes an immutable checkpoint only after a node has
completed successfully.  Effectful handlers remain responsible for performing
their own final cancellation and authorization check at the effect boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
import threading
from types import MappingProxyType


class DagError(RuntimeError):
    """Base class for expected DAG failures."""


class DagValidationError(ValueError):
    """The graph, checkpoint, or a node value violated its contract."""


class DagCancelled(DagError):
    """Execution was cancelled before another result was committed."""


class DagPolicyDenied(DagError):
    """The current policy rejected a node immediately before execution."""


class DagNodeFailed(DagError):
    """A node handler raised an exception."""

    def __init__(self, node_id: str) -> None:
        super().__init__(f"DAG node failed: {node_id}")
        self.node_id = node_id


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 256:
        raise DagValidationError(f"{field} must be a non-empty trimmed string up to 256 characters")
    if "\x00" in value:
        raise DagValidationError(f"{field} cannot contain NUL")
    return value


def _type_name(value: type[object]) -> str:
    return f"{value.__module__}.{value.__qualname__}"


class CancellationToken:
    """Thread-safe, idempotent cooperative cancellation token."""

    def __init__(self) -> None:
        self._cancelled = threading.Event()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def cancel(self) -> None:
        self._cancelled.set()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise DagCancelled("DAG execution was cancelled")


@dataclass(frozen=True, slots=True)
class NodeContext:
    run_id: str
    node_id: str
    inputs: Mapping[str, object]
    cancellation: CancellationToken


NodeHandler = Callable[[NodeContext], object]


@dataclass(frozen=True, slots=True)
class DagNode:
    node_id: str
    dependencies: tuple[str, ...]
    input_types: Mapping[str, type[object]]
    output_type: type[object]
    operation: str
    handler: NodeHandler

    def __post_init__(self) -> None:
        _identifier(self.node_id, "node_id")
        _identifier(self.operation, "operation")
        dependencies = tuple(self.dependencies)
        if len(dependencies) != len(set(dependencies)):
            raise DagValidationError(f"node {self.node_id!r} has duplicate dependencies")
        for dependency in dependencies:
            _identifier(dependency, "dependency")
        if set(self.input_types) != set(dependencies):
            raise DagValidationError(
                f"node {self.node_id!r} input_types must exactly match its dependencies"
            )
        if any(not isinstance(expected, type) for expected in self.input_types.values()):
            raise DagValidationError("input and output contracts must be concrete Python types")
        if not isinstance(self.output_type, type):
            raise DagValidationError("input and output contracts must be concrete Python types")
        if not callable(self.handler):
            raise DagValidationError("handler must be callable")
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(self, "input_types", MappingProxyType(dict(self.input_types)))


@dataclass(frozen=True, slots=True)
class DagSpec:
    graph_id: str
    version: int
    nodes: tuple[DagNode, ...]

    def __post_init__(self) -> None:
        _identifier(self.graph_id, "graph_id")
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise DagValidationError("version must be a positive integer")
        nodes = tuple(self.nodes)
        if not nodes:
            raise DagValidationError("a DAG must contain at least one node")
        by_id = {node.node_id: node for node in nodes}
        if len(by_id) != len(nodes):
            raise DagValidationError("DAG node IDs must be unique")
        for node in nodes:
            unknown = set(node.dependencies) - set(by_id)
            if unknown:
                raise DagValidationError(
                    f"node {node.node_id!r} has unknown dependencies: {sorted(unknown)}"
                )
            if node.node_id in node.dependencies:
                raise DagValidationError(f"node {node.node_id!r} cannot depend on itself")
        object.__setattr__(self, "nodes", nodes)
        self.topological_order()

    @property
    def node_map(self) -> Mapping[str, DagNode]:
        return MappingProxyType({node.node_id: node for node in self.nodes})

    def topological_order(self) -> tuple[str, ...]:
        remaining = {node.node_id: set(node.dependencies) for node in self.nodes}
        order: list[str] = []
        while remaining:
            ready = sorted(node_id for node_id, dependencies in remaining.items() if not dependencies)
            if not ready:
                raise DagValidationError("DAG contains a dependency cycle")
            for node_id in ready:
                order.append(node_id)
                del remaining[node_id]
            for dependencies in remaining.values():
                dependencies.difference_update(ready)
        return tuple(order)

    @property
    def fingerprint(self) -> str:
        body = {
            "graph_id": self.graph_id,
            "version": self.version,
            "nodes": [
                {
                    "node_id": node.node_id,
                    "dependencies": list(node.dependencies),
                    "input_types": {
                        key: _type_name(value)
                        for key, value in sorted(node.input_types.items())
                    },
                    "output_type": _type_name(node.output_type),
                    "operation": node.operation,
                }
                for node in sorted(self.nodes, key=lambda item: item.node_id)
            ],
        }
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class DagCheckpoint:
    graph_fingerprint: str
    completed: Mapping[str, object]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.graph_fingerprint, str)
            or len(self.graph_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in self.graph_fingerprint)
        ):
            raise DagValidationError("graph_fingerprint must be a lowercase SHA-256 digest")
        object.__setattr__(self, "completed", MappingProxyType(dict(self.completed)))


@dataclass(frozen=True, slots=True)
class DagRunResult:
    run_id: str
    outputs: Mapping[str, object]
    executed_nodes: tuple[str, ...]
    resumed_nodes: tuple[str, ...]
    checkpoint: DagCheckpoint


PolicyCheck = Callable[[str, DagNode], bool]
CheckpointSink = Callable[[DagCheckpoint], None]


class DagExecutor:
    """Run a validated graph in stable order with policy and recovery hooks."""

    def __init__(
        self,
        *,
        policy_check: PolicyCheck | None = None,
        checkpoint_sink: CheckpointSink | None = None,
    ) -> None:
        self._policy_check = policy_check or (lambda _run_id, _node: True)
        self._checkpoint_sink = checkpoint_sink

    def run(
        self,
        spec: DagSpec,
        *,
        run_id: str,
        checkpoint: DagCheckpoint | None = None,
        cancellation: CancellationToken | None = None,
    ) -> DagRunResult:
        _identifier(run_id, "run_id")
        token = cancellation or CancellationToken()
        if checkpoint is not None and checkpoint.graph_fingerprint != spec.fingerprint:
            raise DagValidationError("checkpoint belongs to a different DAG contract")
        completed = dict(checkpoint.completed if checkpoint is not None else {})
        node_map = spec.node_map
        unknown = set(completed) - set(node_map)
        if unknown:
            raise DagValidationError(f"checkpoint contains unknown nodes: {sorted(unknown)}")
        for node_id, value in completed.items():
            if not isinstance(value, node_map[node_id].output_type):
                raise DagValidationError(f"checkpoint output type mismatch for node {node_id!r}")
            missing_dependencies = set(node_map[node_id].dependencies) - set(completed)
            if missing_dependencies:
                raise DagValidationError(
                    f"checkpoint node {node_id!r} is missing completed dependencies: "
                    f"{sorted(missing_dependencies)}"
                )

        resumed = tuple(node_id for node_id in spec.topological_order() if node_id in completed)
        executed: list[str] = []
        for node_id in spec.topological_order():
            if node_id in completed:
                continue
            token.raise_if_cancelled()
            node = node_map[node_id]
            inputs = {dependency: completed[dependency] for dependency in node.dependencies}
            for dependency, expected in node.input_types.items():
                if not isinstance(inputs[dependency], expected):
                    raise DagValidationError(
                        f"input type mismatch for {node_id!r} from {dependency!r}"
                    )
            if self._policy_check(run_id, node) is not True:
                raise DagPolicyDenied(f"policy denied operation {node.operation!r}")
            context = NodeContext(
                run_id=run_id,
                node_id=node.node_id,
                inputs=MappingProxyType(inputs),
                cancellation=token,
            )
            try:
                value = node.handler(context)
            except DagError:
                raise
            except Exception as exc:
                raise DagNodeFailed(node.node_id) from exc
            token.raise_if_cancelled()
            if not isinstance(value, node.output_type):
                raise DagValidationError(f"output type mismatch for node {node_id!r}")
            completed[node_id] = value
            executed.append(node_id)
            current = DagCheckpoint(spec.fingerprint, completed)
            if self._checkpoint_sink is not None:
                self._checkpoint_sink(current)

        final_checkpoint = DagCheckpoint(spec.fingerprint, completed)
        return DagRunResult(
            run_id=run_id,
            outputs=MappingProxyType(dict(completed)),
            executed_nodes=tuple(executed),
            resumed_nodes=resumed,
            checkpoint=final_checkpoint,
        )
