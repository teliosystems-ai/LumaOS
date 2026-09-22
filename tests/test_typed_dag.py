from __future__ import annotations

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from luma_os.typed_dag import (  # noqa: E402
    CancellationToken,
    DagCancelled,
    DagCheckpoint,
    DagExecutor,
    DagNode,
    DagPolicyDenied,
    DagSpec,
    DagValidationError,
)


def source(value: int):
    return lambda _context: value


class TypedDagTests(unittest.TestCase):
    def graph(self, seen: list[str] | None = None) -> DagSpec:
        observed = seen if seen is not None else []

        def add(context):
            observed.append(context.node_id)
            return context.inputs["left"] + context.inputs["right"]

        return DagSpec(
            graph_id="sum-v1",
            version=1,
            nodes=(
                DagNode("right", (), {}, int, "read.right", source(4)),
                DagNode("sum", ("left", "right"), {"left": int, "right": int}, int, "sum", add),
                DagNode("left", (), {}, int, "read.left", source(3)),
            ),
        )

    def test_execution_order_types_and_checkpoint_are_deterministic(self) -> None:
        checkpoints: list[DagCheckpoint] = []
        result = DagExecutor(checkpoint_sink=checkpoints.append).run(self.graph(), run_id="run-1")
        self.assertEqual(("left", "right", "sum"), result.executed_nodes)
        self.assertEqual(7, result.outputs["sum"])
        self.assertEqual(3, len(checkpoints))
        self.assertEqual(result.checkpoint.graph_fingerprint, self.graph().fingerprint)

    def test_checkpoint_resume_does_not_repeat_completed_nodes(self) -> None:
        seen: list[str] = []
        graph = self.graph(seen)
        checkpoint = DagCheckpoint(graph.fingerprint, {"left": 3, "right": 4})
        result = DagExecutor().run(graph, run_id="run-2", checkpoint=checkpoint)
        self.assertEqual(("left", "right"), result.resumed_nodes)
        self.assertEqual(("sum",), result.executed_nodes)
        self.assertEqual(["sum"], seen)

    def test_policy_and_cancellation_fail_closed(self) -> None:
        with self.assertRaises(DagPolicyDenied):
            DagExecutor(policy_check=lambda _run, node: node.node_id != "right").run(
                self.graph(), run_id="run-3"
            )
        token = CancellationToken()
        token.cancel()
        with self.assertRaises(DagCancelled):
            DagExecutor().run(self.graph(), run_id="run-4", cancellation=token)

    def test_invalid_graph_checkpoint_and_result_types_are_rejected(self) -> None:
        first = DagNode("first", ("second",), {"second": int}, int, "one", source(1))
        second = DagNode("second", ("first",), {"first": int}, int, "two", source(2))
        with self.assertRaises(DagValidationError):
            DagSpec("cycle", 1, (first, second))

        graph = self.graph()
        with self.assertRaises(DagValidationError):
            DagExecutor().run(
                graph,
                run_id="run-5",
                checkpoint=DagCheckpoint("0" * 64, {}),
            )
        with self.assertRaises(DagValidationError):
            DagExecutor().run(
                graph,
                run_id="run-5b",
                checkpoint=DagCheckpoint(graph.fingerprint, {"sum": 7}),
            )
        bad = DagSpec(
            "bad-output",
            1,
            (DagNode("bad", (), {}, int, "bad", lambda _context: "not-an-int"),),
        )
        with self.assertRaises(DagValidationError):
            DagExecutor().run(bad, run_id="run-6")


if __name__ == "__main__":
    unittest.main()
