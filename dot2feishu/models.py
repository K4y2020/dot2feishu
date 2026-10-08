"""Generic strict MCP Events wire models; contains no probe capabilities."""
from typing import Any, Literal

import mcp_types as types
from pydantic import BaseModel, ConfigDict, Field, SecretStr


class StrictParams(types.RequestParams):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Delivery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["webhook"]
    url: str
    secret: SecretStr | None = None


class EventParams(StrictParams):
    name: str
    arguments: dict[str, Any]
    delivery: Delivery
    cursor: str | None = None
    ttl_ms: int | None = Field(default=86400000, alias="ttlMs", strict=True)


class ListParams(StrictParams):
    cursor: str | None = None


class UnsubscribeDelivery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["webhook"]
    url: str


class UnsubscribeParams(StrictParams):
    name: str
    arguments: dict[str, Any]
    delivery: UnsubscribeDelivery

