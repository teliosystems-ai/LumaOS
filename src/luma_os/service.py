"""Composition root for the local Luma OS developer MVP."""

from __future__ import annotations

from typing import Any

from .artifacts import ArtifactService, ReceiptService
from .config import LumaConfig
from .db import LumaStore
from .grants import FolderGrantService
from .models import OpenAICompatibleClient
from .workflows import InvoiceWorkflowService


class LumaService:
    version = "0.1.0"

    def __init__(self, config: LumaConfig) -> None:
        config.ensure_directories()
        self.config = config
        self.store = LumaStore(config.db_path)
        self.receipts = ReceiptService(self.store)
        self.grants = FolderGrantService(self.store, max_source_bytes=config.max_source_bytes)
        self.artifacts = ArtifactService(self.store, config.objects_dir, self.receipts)
        self.workflows = InvoiceWorkflowService(self.store, self.grants, self.artifacts)
        self.models = OpenAICompatibleClient(
            config.model_endpoint,
            config.model_name,
            api_key=config.model_api_key,
        )

    @classmethod
    def from_env(cls, *, data_dir: str | None = None) -> "LumaService":
        return cls(LumaConfig.from_env(data_dir=data_dir))

    def health(self) -> dict[str, Any]:
        return {"status": "ok", "service": "luma-os", "version": self.version}

    def status(self) -> dict[str, Any]:
        return {
            "status": "ready",
            "version": self.version,
            "profile": "developer-mvp",
            "offline_capable": True,
            "production_security_claim": False,
            "counts": self.store.counts(),
            "data_dir": str(self.config.data_dir),
        }
