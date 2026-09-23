from __future__ import annotations

import argparse
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.smoke_local_model import (  # noqa: E402
    JSON_SAFE_INTEGER_MAX,
    _domain_bytes,
    _parser,
    _positive_json_safe_integer,
)


class SmokeLocalModelArgumentTests(unittest.TestCase):
    def test_resource_values_are_positive_json_safe_integers(self) -> None:
        self.assertEqual(("host", JSON_SAFE_INTEGER_MAX), _domain_bytes(
            f"host={JSON_SAFE_INTEGER_MAX}"
        ))
        self.assertEqual(
            JSON_SAFE_INTEGER_MAX,
            _positive_json_safe_integer(str(JSON_SAFE_INTEGER_MAX)),
        )
        for value in ("0", "-1", str(JSON_SAFE_INTEGER_MAX + 1), "1.5"):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    _domain_bytes(f"host={value}")
                with self.assertRaises(argparse.ArgumentTypeError):
                    _positive_json_safe_integer(value)

    def test_parser_accepts_multiple_explicit_resource_domains(self) -> None:
        parsed = _parser().parse_args(
            [
                "--model-sha256",
                "a" * 64,
                "--domain-budget",
                "accelerator=4096",
                "--domain-budget",
                "host=8192",
                "--reservation",
                "accelerator=2048",
                "--reservation",
                "host=4096",
            ]
        )
        self.assertEqual(
            [("accelerator", 4096), ("host", 8192)], parsed.domain_budget
        )
        self.assertEqual(
            [("accelerator", 2048), ("host", 4096)], parsed.reservation
        )


if __name__ == "__main__":
    unittest.main()
