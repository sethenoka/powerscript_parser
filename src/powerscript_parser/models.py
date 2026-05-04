from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SourceFile:
    """A readable file from disk or an archive."""

    display_path: str
    name: str
    text: str
    container_path: str | None = None
    modified_time: str | None = None


@dataclass
class Event:
    artifact: str
    event_type: str
    source_path: str
    timestamp_raw: str | None = None
    timestamp: str | None = None
    timezone: str = "UTC"
    user: str | None = None
    run_as_user: str | None = None
    host: str | None = None
    machine: str | None = None
    command_text: str | None = None
    raw_block: str | None = None
    command_index: int | None = None
    line_number: int | None = None
    source_mtime: str | None = None
    container_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "event_type": self.event_type,
            "source_path": self.source_path,
            "container_path": self.container_path,
            "timestamp_raw": self.timestamp_raw,
            "timestamp": self.timestamp,
            "timezone": self.timezone,
            "user": self.user,
            "run_as_user": self.run_as_user,
            "host": self.host,
            "machine": self.machine,
            "command_index": self.command_index,
            "line_number": self.line_number,
            "command_text": self.command_text,
            "raw_block": self.raw_block,
            "source_mtime": self.source_mtime,
            "metadata": self.metadata,
        }


def path_label(path: Path) -> str:
    try:
        return str(path.resolve())
    except OSError:
        return str(path)
