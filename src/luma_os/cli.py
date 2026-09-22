"""Command-line entry point for the Luma OS developer MVP."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .errors import LumaError
from .server import create_server
from .service import LumaService


def _service(data_dir: str | None) -> LumaService:
    return LumaService.from_env(data_dir=data_dir)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="luma-os", description="Luma OS local developer MVP")
    subparsers = parser.add_subparsers(dest="command", required=True)

    initialize = subparsers.add_parser("init", help="Initialize the local durable store")
    initialize.add_argument("--data-dir")

    status = subparsers.add_parser("status", help="Show local control-plane status")
    status.add_argument("--data-dir")

    serve = subparsers.add_parser("serve", help="Serve the local API and web workspace")
    serve.add_argument("--data-dir")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--web-root", type=Path, default=None)
    serve.add_argument(
        "--unsafe-allow-network",
        action="store_true",
        help="Allow a non-loopback bind for isolated development only",
    )
    serve.add_argument("--print-token", action="store_true", help="Print the temporary bearer token")

    enroll = subparsers.add_parser("enroll", help="Enroll an input folder")
    enroll.add_argument("path")
    enroll.add_argument("--data-dir")
    enroll.add_argument("--owner", default="local-user")
    enroll.add_argument("--read-write", action="store_true")

    run = subparsers.add_parser("run-invoices", help="Create and run an invoice report from enrolled files")
    run.add_argument("grant_id")
    run.add_argument("files", nargs="+")
    run.add_argument("--data-dir")
    run.add_argument("--owner", default="local-user")
    run.add_argument("--currency")
    run.add_argument("--idempotency-key")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        service = _service(args.data_dir)
        if args.command == "init":
            print(json.dumps(service.status(), indent=2))
            return 0
        if args.command == "status":
            print(json.dumps(service.status(), indent=2))
            return 0
        if args.command == "enroll":
            grant = service.grants.enroll(
                args.owner,
                args.path,
                scope="read_write" if args.read_write else "read",
            )
            print(json.dumps(grant, indent=2))
            return 0
        if args.command == "run-invoices":
            workflow = service.workflows.submit(
                args.owner,
                grant_id=args.grant_id,
                files=args.files,
                currency=args.currency,
                idempotency_key=args.idempotency_key,
            )
            result = service.workflows.run(args.owner, workflow["workflow_id"])
            print(json.dumps(result, indent=2))
            return 0 if result["state"] == "SUCCEEDED" else 2
        if args.command == "serve":
            server = create_server(
                service,
                host=args.host,
                port=args.port,
                web_root=args.web_root,
                unsafe_allow_network=args.unsafe_allow_network,
            )
            display_host = args.host or service.config.host
            print(f"Luma OS developer MVP: http://{display_host}:{server.local_port}")
            print("Loopback developer preview; this is not a production security boundary.")
            if args.print_token:
                print(f"Temporary bearer token: {server.session_token}")
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
            return 0
    except LumaError as exc:
        print(json.dumps(exc.as_dict(), indent=2), file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
