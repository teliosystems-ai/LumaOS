"""Durable, replay-safe invoice-to-report developer workflow."""

from __future__ import annotations

import csv
from datetime import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
from pathlib import PurePath
import re
from typing import Any, Iterable
import uuid

from .artifacts import ArtifactService
from .db import LumaStore, utc_now
from .errors import ConflictError, NotFoundError, ValidationError
from .grants import FolderGrantService


WORKFLOW_TYPE = "invoice_report.v1"
STEP_IDS = ("read_sources", "extract_rows", "aggregate", "publish_csv", "publish_report")
TERMINAL_STATES = {"SUCCEEDED", "FAILED", "CANCELLED"}


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class NeedsManualInput(Exception):
    def __init__(self, issues: list[dict[str, str]]) -> None:
        super().__init__("Invoice data needs manual review")
        self.issues = issues


class InvoiceWorkflowService:
    """Service layer suitable for CLI or HTTP adapters.

    Model output is not used for totals or completion. Parsing, arithmetic,
    artifact commits, and state transitions remain deterministic.
    """

    def __init__(self, store: LumaStore, grants: FolderGrantService, artifacts: ArtifactService) -> None:
        self.store = store
        self.grants = grants
        self.artifacts = artifacts
        self._recover_interrupted()

    def _recover_interrupted(self) -> None:
        """Make work left RUNNING by a stopped single-process service replayable."""

        recovered = _json({"code": "interrupted", "message": "Previous execution stopped and is safe to retry."})
        with self.store.transaction(write=True) as connection:
            workflow_ids = [
                row[0] for row in connection.execute("SELECT workflow_id FROM workflows WHERE state='RUNNING'").fetchall()
            ]
            if workflow_ids:
                placeholders = ",".join("?" for _ in workflow_ids)
                connection.execute(
                    f"UPDATE workflow_steps SET state='PENDING',error_json=?,updated_at=? "
                    f"WHERE state='RUNNING' AND workflow_id IN ({placeholders})",
                    (recovered, utc_now(), *workflow_ids),
                )
                connection.execute(
                    f"UPDATE workflows SET state='VALIDATED',error_json=?,updated_at=? "
                    f"WHERE workflow_id IN ({placeholders})",
                    (recovered, utc_now(), *workflow_ids),
                )

    def submit(
        self,
        owner: str,
        *,
        grant_id: str | None = None,
        files: list[str] | None = None,
        source_text: str | None = None,
        source_format: str = "text",
        source_name: str = "pasted-invoices.txt",
        currency: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        owner = owner.strip()
        if not owner:
            raise ValidationError("Owner is required")
        source_files = files or []
        if len(source_files) > 100:
            raise ValidationError("A workflow can include at most 100 files")
        if source_files and not grant_id:
            raise ValidationError("grant_id is required when files are provided")
        if not source_files and source_text is None:
            raise ValidationError("Provide enrolled files or pasted invoice text")
        if source_text is not None and not source_text.strip():
            raise ValidationError("Pasted invoice text cannot be empty")
        if source_text is not None and len(source_text.encode("utf-8")) > self.grants.max_source_bytes:
            raise ValidationError("Pasted invoice text exceeds the configured size limit")
        if source_format not in {"text", "csv"}:
            raise ValidationError("source_format must be 'text' or 'csv'")
        if "/" in source_name or "\\" in source_name or source_name in {"", ".", ".."}:
            raise ValidationError("source_name must be a simple filename")
        if currency is not None:
            currency = self._currency(currency)

        normalized_files: list[str] = []
        if grant_id:
            self.grants.get(owner, grant_id)
        for relative_path in source_files:
            inspected = self.grants.inspect_file(owner, str(grant_id), relative_path)
            normalized_files.append(str(inspected["relative_path"]))

        request: dict[str, Any] = {
            "grant_id": grant_id,
            "files": normalized_files,
            "currency": currency,
        }
        if source_text is not None:
            request["inline_source"] = {
                "text": source_text,
                "format": source_format,
                "name": source_name,
                "sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
            }
        request_json = _json(request)
        request_hash = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        key = (idempotency_key or str(uuid.uuid4())).strip()
        if not key or len(key) > 250:
            raise ValidationError("Idempotency key must be between 1 and 250 characters")

        now = utc_now()
        with self.store.transaction(write=True) as connection:
            existing = connection.execute(
                "SELECT workflow_id,request_hash FROM workflows WHERE owner=? AND workflow_type=? AND idempotency_key=?",
                (owner, WORKFLOW_TYPE, key),
            ).fetchone()
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise ConflictError("Idempotency key was already used with a different workflow request")
                workflow_id = existing["workflow_id"]
            else:
                workflow_id = str(uuid.uuid4())
                connection.execute(
                    "INSERT INTO workflows(workflow_id,owner,workflow_type,idempotency_key,request_hash,request_json,state,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,?,'VALIDATED',?,?)",
                    (workflow_id, owner, WORKFLOW_TYPE, key, request_hash, request_json, now, now),
                )
                connection.executemany(
                    "INSERT INTO workflow_steps(workflow_id,step_id,position,state,updated_at) VALUES (?,?,?,'PENDING',?)",
                    [(workflow_id, step, position, now) for position, step in enumerate(STEP_IDS)],
                )
        return self.get(owner, workflow_id)

    def run(self, owner: str, workflow_id: str) -> dict[str, Any]:
        workflow = self.get(owner, workflow_id)
        if workflow["state"] == "SUCCEEDED":
            return workflow
        if workflow["state"] == "CANCELLED":
            raise ConflictError("Cancelled workflow cannot be run")
        if workflow["state"] == "RUNNING":
            raise ConflictError("Workflow is already running")
        if workflow["state"] == "WAITING_USER" and workflow.get("manual_input") is None:
            return workflow

        now = utc_now()
        with self.store.transaction(write=True) as connection:
            changed = connection.execute(
                "UPDATE workflows SET state='RUNNING',attempt=attempt+1,error_json=NULL,updated_at=? "
                "WHERE workflow_id=? AND owner=? AND state NOT IN ('RUNNING','SUCCEEDED','CANCELLED')",
                (now, workflow_id, owner),
            ).rowcount
            if not changed:
                return self.get(owner, workflow_id)

        try:
            request = workflow["request"]
            manual = workflow.get("manual_input")
            self._step(workflow_id, "read_sources", "RUNNING", increment=True)
            sources = self._read_sources(owner, request)
            self._step(workflow_id, "read_sources", "SUCCEEDED")

            self._step(workflow_id, "extract_rows", "RUNNING", increment=True)
            if manual is not None:
                rows = [self._normalize_manual_row(row, index) for index, row in enumerate(manual["rows"])]
            else:
                rows = self._extract_sources(sources, requested_currency=request.get("currency"))
            self._step(workflow_id, "extract_rows", "SUCCEEDED")

            self._step(workflow_id, "aggregate", "RUNNING", increment=True)
            aggregates = self._aggregate(rows)
            self._step(workflow_id, "aggregate", "SUCCEEDED")

            provenance = {
                "workflow_id": workflow_id,
                "workflow_type": WORKFLOW_TYPE,
                "source_refs": [source["reference"] for source in sources],
                "row_count": len(rows),
                "manual_input": manual is not None,
            }
            self._step(workflow_id, "publish_csv", "RUNNING", increment=True)
            csv_artifact = self.artifacts.create_text(
                owner,
                self._report_csv(aggregates),
                filename="invoice-summary.csv",
                media_type="text/csv; charset=utf-8",
                provenance=provenance,
                idempotency_key=f"workflow:{workflow_id}:invoice-summary-csv:v1",
                workflow_id=workflow_id,
                step_id="publish_csv",
            )
            self._step(workflow_id, "publish_csv", "SUCCEEDED")

            self._step(workflow_id, "publish_report", "RUNNING", increment=True)
            report_artifact = self.artifacts.create_text(
                owner,
                self._report_markdown(rows, aggregates),
                filename="invoice-report.md",
                media_type="text/markdown; charset=utf-8",
                provenance=provenance,
                idempotency_key=f"workflow:{workflow_id}:invoice-report-md:v1",
                workflow_id=workflow_id,
                step_id="publish_report",
            )
            self._step(workflow_id, "publish_report", "SUCCEEDED")
            result = {
                "row_count": len(rows),
                "summary": aggregates,
                "artifacts": [csv_artifact, report_artifact],
            }
            with self.store.transaction(write=True) as connection:
                connection.execute(
                    "UPDATE workflows SET state='SUCCEEDED',result_json=?,error_json=NULL,updated_at=? WHERE workflow_id=? AND owner=?",
                    (_json(result), utc_now(), workflow_id, owner),
                )
            return self.get(owner, workflow_id)
        except NeedsManualInput as exc:
            fallback = {
                "message": "Some invoice data could not be parsed deterministically. Review and submit explicit rows.",
                "issues": exc.issues,
                "required_fields": ["date", "amount"],
                "optional_fields": ["currency", "vendor", "source"],
            }
            with self.store.transaction(write=True) as connection:
                connection.execute(
                    "UPDATE workflows SET state='WAITING_USER',result_json=?,error_json=?,updated_at=? WHERE workflow_id=? AND owner=?",
                    (_json({"manual_fallback": fallback}), _json({"code": "manual_input_required"}), utc_now(), workflow_id, owner),
                )
            self._step(workflow_id, "extract_rows", "WAITING_USER", error={"issues": exc.issues})
            return self.get(owner, workflow_id)
        except Exception as exc:
            error = {"code": "workflow_failed", "message": str(exc)}
            with self.store.transaction(write=True) as connection:
                connection.execute(
                    "UPDATE workflows SET state='FAILED',error_json=?,updated_at=? WHERE workflow_id=? AND owner=?",
                    (_json(error), utc_now(), workflow_id, owner),
                )
                connection.execute(
                    "UPDATE workflow_steps SET state='FAILED',error_json=?,updated_at=? WHERE workflow_id=? AND state='RUNNING'",
                    (_json(error), utc_now(), workflow_id),
                )
            raise

    def provide_manual_rows(self, owner: str, workflow_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
        workflow = self.get(owner, workflow_id)
        if workflow["state"] not in {"WAITING_USER", "FAILED", "VALIDATED"}:
            raise ConflictError("Manual rows can only be supplied before a workflow succeeds")
        if not rows or len(rows) > 10_000:
            raise ValidationError("Provide between 1 and 10,000 invoice rows")
        normalized = [self._normalize_manual_row(row, index) for index, row in enumerate(rows)]
        with self.store.transaction(write=True) as connection:
            connection.execute(
                "UPDATE workflows SET manual_input_json=?,state='VALIDATED',result_json=NULL,error_json=NULL,updated_at=? "
                "WHERE workflow_id=? AND owner=?",
                (_json({"rows": normalized}), utc_now(), workflow_id, owner),
            )
            connection.execute(
                "UPDATE workflow_steps SET state='PENDING',error_json=NULL,updated_at=? WHERE workflow_id=? AND step_id IN ('extract_rows','aggregate','publish_csv','publish_report')",
                (utc_now(), workflow_id),
            )
        return self.get(owner, workflow_id)

    def cancel(self, owner: str, workflow_id: str) -> dict[str, Any]:
        workflow = self.get(owner, workflow_id)
        if workflow["state"] == "SUCCEEDED":
            raise ConflictError("Completed workflow cannot be cancelled")
        with self.store.transaction(write=True) as connection:
            connection.execute(
                "UPDATE workflows SET state='CANCELLED',updated_at=? WHERE workflow_id=? AND owner=?",
                (utc_now(), workflow_id, owner),
            )
            connection.execute(
                "UPDATE workflow_steps SET state='CANCELLED',updated_at=? WHERE workflow_id=? AND state IN ('PENDING','RUNNING','WAITING_USER')",
                (utc_now(), workflow_id),
            )
        return self.get(owner, workflow_id)

    def get(self, owner: str, workflow_id: str) -> dict[str, Any]:
        with self.store.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM workflows WHERE workflow_id=? AND owner=?", (workflow_id, owner)
            ).fetchone()
            if row is None:
                raise NotFoundError("Workflow was not found")
            steps = connection.execute(
                "SELECT * FROM workflow_steps WHERE workflow_id=? ORDER BY position", (workflow_id,)
            ).fetchall()
        return self._workflow_row(row, steps)

    def list(self, owner: str, *, limit: int = 100) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self.store.transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM workflows WHERE owner=? ORDER BY updated_at DESC LIMIT ?", (owner, limit)
            ).fetchall()
        return [self._workflow_row(row, []) for row in rows]

    def _read_sources(self, owner: str, request: dict[str, Any]) -> list[dict[str, Any]]:
        sources: list[dict[str, Any]] = []
        grant_id = request.get("grant_id")
        for path in request.get("files", []):
            safe_file = self.grants.read_file(owner, grant_id, path)
            sources.append(
                {
                    "name": PurePath(path).name,
                    "format": "csv" if path.lower().endswith(".csv") else "text",
                    "content": safe_file.content,
                    "reference": {
                        "grant_id": grant_id,
                        "relative_path": path,
                        "sha256": hashlib.sha256(safe_file.content).hexdigest(),
                        "size_bytes": safe_file.size_bytes,
                    },
                }
            )
        inline = request.get("inline_source")
        if inline:
            content = inline["text"].encode("utf-8")
            sources.append(
                {
                    "name": inline["name"],
                    "format": inline["format"],
                    "content": content,
                    "reference": {
                        "inline_name": inline["name"],
                        "sha256": inline["sha256"],
                        "size_bytes": len(content),
                    },
                }
            )
        return sources

    def _extract_sources(self, sources: list[dict[str, Any]], *, requested_currency: str | None) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        issues: list[dict[str, str]] = []
        for source in sources:
            try:
                text = source["content"].decode("utf-8-sig")
                if source["format"] == "csv":
                    rows.extend(self._parse_csv(text, source["name"], requested_currency))
                else:
                    rows.append(self._parse_text(text, source["name"], requested_currency))
            except (UnicodeDecodeError, ValidationError) as exc:
                issues.append({"source": source["name"], "message": str(exc)})
        if issues:
            raise NeedsManualInput(issues)
        if not rows:
            raise NeedsManualInput([{"source": "input", "message": "No invoice rows were found"}])
        return rows

    def _parse_csv(self, text: str, source: str, requested_currency: str | None) -> list[dict[str, str]]:
        try:
            dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        if not reader.fieldnames:
            raise ValidationError("CSV is missing a header row")
        header_map = {self._header(name): name for name in reader.fieldnames if name is not None}
        date_field = self._pick(header_map, "invoice_date", "billing_date", "date", "month")
        amount_field = self._pick(header_map, "invoice_total", "total_amount", "amount", "total", "cost")
        currency_field = self._pick(header_map, "currency", "currency_code", required=False)
        vendor_field = self._pick(header_map, "vendor", "supplier", "merchant", "company", required=False)
        parsed: list[dict[str, str]] = []
        for row_number, raw in enumerate(reader, start=2):
            if not any(str(value or "").strip() for value in raw.values()):
                continue
            try:
                date_value = self._date(str(raw.get(date_field, "")))
                amount_value, inferred = self._amount(str(raw.get(amount_field, "")))
                detected_currency = (
                    self._currency(str(raw.get(currency_field, "")))
                    if currency_field and str(raw.get(currency_field, "")).strip()
                    else inferred
                )
                if requested_currency and detected_currency and requested_currency != detected_currency:
                    raise ValidationError("Currency conversion is not supported; source and requested currencies differ")
                currency_value = detected_currency or requested_currency or "USD"
            except ValidationError as exc:
                raise ValidationError(f"CSV row {row_number}: {exc}") from exc
            parsed.append(
                {
                    "date": date_value,
                    "month": date_value[:7],
                    "amount": format(amount_value, "f"),
                    "currency": currency_value,
                    "vendor": str(raw.get(vendor_field, "")).strip() if vendor_field else "",
                    "source": f"{source}:row-{row_number}",
                }
            )
        if not parsed:
            raise ValidationError("CSV contains no invoice records")
        return parsed

    def _parse_text(self, text: str, source: str, requested_currency: str | None) -> dict[str, str]:
        fields: dict[str, str] = {}
        aliases = {
            "date": r"(?:invoice\s+date|billing\s+date|date|month)",
            "amount": r"(?:invoice\s+total|total\s+amount|amount|total|cost)",
            "currency": r"(?:currency|currency\s+code)",
            "vendor": r"(?:vendor|supplier|merchant|company)",
        }
        for field, alias in aliases.items():
            match = re.search(rf"(?im)^\s*{alias}\s*[:=]\s*(.+?)\s*$", text)
            if match:
                fields[field] = match.group(1).strip()
        if "date" not in fields or "amount" not in fields:
            raise ValidationError("Text invoice requires labelled Date and Amount fields")
        date_value = self._date(fields["date"])
        amount, inferred = self._amount(fields["amount"])
        detected_currency = self._currency(fields["currency"]) if fields.get("currency") else inferred
        if requested_currency and detected_currency and requested_currency != detected_currency:
            raise ValidationError("Currency conversion is not supported; source and requested currencies differ")
        currency = detected_currency or requested_currency or "USD"
        return {
            "date": date_value,
            "month": date_value[:7],
            "amount": format(amount, "f"),
            "currency": currency,
            "vendor": fields.get("vendor", ""),
            "source": source,
        }

    def _normalize_manual_row(self, row: dict[str, Any], index: int) -> dict[str, str]:
        if not isinstance(row, dict):
            raise ValidationError(f"Manual row {index + 1} must be an object")
        date_value = self._date(str(row.get("date", "")))
        amount, inferred = self._amount(str(row.get("amount", "")))
        currency = self._currency(str(row.get("currency") or inferred or "USD"))
        return {
            "date": date_value,
            "month": date_value[:7],
            "amount": format(amount, "f"),
            "currency": currency,
            "vendor": str(row.get("vendor", "")).strip()[:300],
            "source": str(row.get("source", f"manual-row-{index + 1}")).strip()[:500],
        }

    @staticmethod
    def _date(raw: str) -> str:
        value = raw.strip()
        formats = ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m", "%B %Y", "%b %Y")
        for date_format in formats:
            try:
                parsed = datetime.strptime(value, date_format)
                return parsed.strftime("%Y-%m-%d") if "%d" in date_format else parsed.strftime("%Y-%m-01")
            except ValueError:
                pass
        numeric = re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{4})", value)
        if numeric:
            first, second = int(numeric.group(1)), int(numeric.group(2))
            if first <= 12 and second <= 12:
                raise ValidationError("Ambiguous numeric date; use YYYY-MM-DD")
            date_format = "%d/%m/%Y" if first > 12 else "%m/%d/%Y"
            try:
                return datetime.strptime(value, date_format).strftime("%Y-%m-%d")
            except ValueError:
                pass
        raise ValidationError("Date must be an unambiguous date such as YYYY-MM-DD")

    @staticmethod
    def _amount(raw: str) -> tuple[Decimal, str | None]:
        value = raw.strip()
        currency_codes = {code.upper() for code in re.findall(r"(?i)\b(USD|EUR|GBP|CAD|AUD|JPY|CHF)\b", value)}
        if len(currency_codes) > 1:
            raise ValidationError("Amount contains multiple currency codes")
        inferred = next(iter(currency_codes)) if currency_codes else (
            "USD" if "$" in value else "EUR" if "€" in value else "GBP" if "£" in value else None
        )
        value = re.sub(r"(?i)\b(?:USD|EUR|GBP|CAD|AUD|JPY|CHF)\b", "", value)
        value = value.replace("$", "").replace("€", "").replace("£", "").replace(" ", "")
        negative = value.startswith("(") and value.endswith(")")
        value = value.strip("()")
        if "," in value and "." in value:
            if value.rfind(",") > value.rfind("."):
                value = value.replace(".", "").replace(",", ".")
            else:
                value = value.replace(",", "")
        elif "," in value:
            suffix = value.rsplit(",", 1)[1]
            value = value.replace(",", ".") if len(suffix) in {1, 2} else value.replace(",", "")
        if negative:
            value = "-" + value
        try:
            amount = Decimal(value)
        except InvalidOperation as exc:
            raise ValidationError("Amount is not a valid decimal number") from exc
        if not amount.is_finite():
            raise ValidationError("Amount must be finite")
        return amount.quantize(Decimal("0.01")), inferred

    @staticmethod
    def _currency(raw: str) -> str:
        value = raw.strip().upper()
        if not re.fullmatch(r"[A-Z]{3}", value):
            raise ValidationError("Currency must be a three-letter code")
        return value

    @staticmethod
    def _header(raw: str) -> str:
        return re.sub(r"[^a-z0-9]+", "_", raw.strip().lower()).strip("_")

    @staticmethod
    def _pick(headers: dict[str, str], *names: str, required: bool = True) -> str | None:
        for name in names:
            if name in headers:
                return headers[name]
        if required:
            raise ValidationError(f"CSV requires one of these columns: {', '.join(names)}")
        return None

    @staticmethod
    def _aggregate(rows: Iterable[dict[str, str]]) -> list[dict[str, Any]]:
        values: dict[tuple[str, str], tuple[int, Decimal]] = {}
        for row in rows:
            key = (row["month"], row["currency"])
            count, total = values.get(key, (0, Decimal("0")))
            values[key] = (count + 1, total + Decimal(row["amount"]))
        return [
            {"month": month, "currency": currency, "invoice_count": count, "total": format(total, ".2f")}
            for (month, currency), (count, total) in sorted(values.items())
        ]

    @staticmethod
    def _report_csv(aggregates: list[dict[str, Any]]) -> str:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["month", "currency", "invoice_count", "total"])
        for row in aggregates:
            writer.writerow([row["month"], row["currency"], row["invoice_count"], row["total"]])
        return stream.getvalue()

    @staticmethod
    def _report_markdown(rows: list[dict[str, str]], aggregates: list[dict[str, Any]]) -> str:
        lines = [
            "# Invoice report",
            "",
            f"Processed {len(rows)} invoice record{'s' if len(rows) != 1 else ''}.",
            "",
            "| Month | Currency | Invoices | Total |",
            "|---|---:|---:|---:|",
        ]
        lines.extend(
            f"| {row['month']} | {row['currency']} | {row['invoice_count']} | {row['total']} |"
            for row in aggregates
        )
        lines.extend(["", "## Sources", ""])
        for row in rows:
            vendor = f" — {row['vendor']}" if row["vendor"] else ""
            lines.append(f"- {row['date']}: {row['currency']} {row['amount']}{vendor} ({row['source']})")
        lines.append("")
        return "\n".join(lines)

    def _step(
        self,
        workflow_id: str,
        step_id: str,
        state: str,
        *,
        increment: bool = False,
        error: dict[str, Any] | None = None,
    ) -> None:
        with self.store.transaction(write=True) as connection:
            connection.execute(
                "UPDATE workflow_steps SET state=?,attempt=attempt+?,error_json=?,updated_at=? WHERE workflow_id=? AND step_id=?",
                (state, 1 if increment else 0, _json(error) if error else None, utc_now(), workflow_id, step_id),
            )

    @staticmethod
    def _workflow_row(row: object, steps: Iterable[object]) -> dict[str, Any]:
        return {
            "workflow_id": row["workflow_id"],  # type: ignore[index]
            "id": row["workflow_id"],  # type: ignore[index]
            "owner": row["owner"],  # type: ignore[index]
            "type": row["workflow_type"],  # type: ignore[index]
            "kind": row["workflow_type"],  # type: ignore[index]
            "idempotency_key": row["idempotency_key"],  # type: ignore[index]
            "state": row["state"],  # type: ignore[index]
            "attempt": int(row["attempt"]),  # type: ignore[index]
            "request": json.loads(row["request_json"]),  # type: ignore[index]
            "manual_input": json.loads(row["manual_input_json"]) if row["manual_input_json"] else None,  # type: ignore[index]
            "result": json.loads(row["result_json"]) if row["result_json"] else None,  # type: ignore[index]
            "error": json.loads(row["error_json"]) if row["error_json"] else None,  # type: ignore[index]
            "created_at": row["created_at"],  # type: ignore[index]
            "updated_at": row["updated_at"],  # type: ignore[index]
            "steps": [
                {
                    "step_id": step["step_id"],
                    "position": int(step["position"]),
                    "state": step["state"],
                    "attempt": int(step["attempt"]),
                    "error": json.loads(step["error_json"]) if step["error_json"] else None,
                    "updated_at": step["updated_at"],
                }
                for step in steps
            ],
        }
