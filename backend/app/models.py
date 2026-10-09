from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field

Verdict = Literal["SAFE", "CAUTION", "DANGER"]
Intent = Literal["pay_shop", "receive", "pay_bill", "check"]


@dataclass
class Signal:
    code: str
    weight: int
    params: dict[str, Any] = field(default_factory=dict)
    variant: str | None = None  # selects a per-category text, e.g. UPI_SCAM_KEYWORD.refund
    force: Verdict | None = None  # hard override of the verdict

    @property
    def severity(self) -> str:
        if self.force == "DANGER" or self.weight >= 60:
            return "critical"
        if self.weight < 0:
            return "good"
        if self.weight == 0:
            return "info"
        if self.weight < 15:
            return "low"
        if self.weight < 35:
            return "medium"
        return "high"


@dataclass
class Check:
    name: str
    status: Literal["ok", "skipped", "timeout", "error", "demo", "cached"]
    ms: int = 0
    detail: str = ""


@dataclass
class Analysis:
    """Mutable result built up by an analyzer."""
    kind: str
    headline_code: str = "HEAD_TEXT"
    headline_params: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    signals: list[Signal] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)

    def add(self, code: str, weight: int, variant: str | None = None,
            force: Verdict | None = None, **params: Any) -> Signal:
        s = Signal(code=code, weight=weight, params=params, variant=variant, force=force)
        self.signals.append(s)
        return s

    def has(self, code: str) -> bool:
        return any(s.code == code for s in self.signals)


# ------------------------------------------------------------------ API schemas
class AnalyzeRequest(BaseModel):
    payload: str = Field(..., max_length=4096)
    intent: Intent = "check"
    source: Literal["camera", "image", "text"] = "camera"


class ReportRequest(BaseModel):
    payload: str = Field(..., max_length=4096)
    reason: str = Field("", max_length=300)


class ShopRegisterRequest(BaseModel):
    payload: str = Field(..., max_length=4096)
    shop_name: str = Field("", max_length=100)


class ShopVerifyRequest(BaseModel):
    payload: str = Field(..., max_length=4096)
    shop_code: str | None = Field(None, max_length=12)
    expected_vpa: str | None = Field(None, max_length=255)
    expected_name: str | None = Field(None, max_length=255)
