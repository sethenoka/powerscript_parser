from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from .models import Event
from .timeutils import filesystem_timestamp

L2T_COLUMNS = [
    "date",
    "time",
    "timezone",
    "MACB",
    "source",
    "sourcetype",
    "type",
    "user",
    "host",
    "short",
    "desc",
    "version",
    "filename",
    "inode",
    "notes",
    "format",
    "extra",
]

CSV_COLUMNS = [
    "artifact",
    "event_type",
    "timestamp",
    "timestamp_raw",
    "timezone",
    "user",
    "run_as_user",
    "is_impersonated",
    "machine",
    "host_application",
    "process_id",
    "ps_version",
    "command_index",
    "line_number",
    "raw_block",
    "encoded_command",
    "decoded_command",
    "decoded_command_status",
    "decoded_command_depth",
    "decoded_command_source",
    "source_path",
    "container_path",
    "source_mtime",
]

ENCODED_COMMAND_VALUE_RE = re.compile(r"(?i)((?:-|/)encodedcommand|(?:-|/)enc)\s+([A-Za-z0-9+/=]+)")


def resolve_output_path(output: Path | None, output_format: str) -> Path:
    extension = {"l2tcsv": "csv", "csv": "csv", "json": "json", "xml": "xml"}[output_format]
    filename = f"powerscript_parser_{filesystem_timestamp()}.{extension}"
    if output is None:
        return Path.cwd() / filename
    if output.exists() and output.is_dir():
        return output / filename
    if output.suffix:
        return output
    return output / filename


def write_events(events: list[Event], output_path: Path, output_format: str) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_format == "l2tcsv":
        _write_l2tcsv(events, output_path)
    elif output_format == "csv":
        _write_csv(events, output_path)
    elif output_format == "json":
        _write_json(events, output_path)
    elif output_format == "xml":
        _write_xml(events, output_path)
    else:
        raise ValueError(f"unsupported output format: {output_format}")


def _write_l2tcsv(events: list[Event], output_path: Path) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=L2T_COLUMNS, lineterminator="\n")
        writer.writeheader()
        metadata_cache: dict[int, str] = {}
        for event in events:
            writer.writerow(_to_l2t_row(event, metadata_cache))


def _write_csv(events: list[Event], output_path: Path) -> None:
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for event in events:
            writer.writerow(_to_csv_row(event))


def _write_json(events: list[Event], output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump([event.to_dict() for event in events], handle, indent=2, sort_keys=True)
        handle.write("\n")


def _write_xml(events: list[Event], output_path: Path) -> None:
    root = ElementTree.Element("powerscript_parser_events")
    for event in events:
        event_element = ElementTree.SubElement(root, "event")
        _append_xml_value(event_element, event.to_dict())
    tree = ElementTree.ElementTree(root)
    ElementTree.indent(tree, space="  ")
    tree.write(output_path, encoding="utf-8", xml_declaration=True)


def _append_xml_value(parent: ElementTree.Element, value: Any) -> None:
    if isinstance(value, dict):
        for key, child_value in value.items():
            child = ElementTree.SubElement(parent, str(key))
            _append_xml_value(child, child_value)
    elif value is not None:
        parent.text = str(value)


def _to_l2t_row(event: Event, metadata_cache: dict[int, str]) -> dict[str, str]:
    date_value = ""
    time_value = ""
    if event.timestamp:
        date_value = event.timestamp[:10]
        time_value = event.timestamp[11:]

    short = event.command_text or ""
    one_line_short = " ".join(short.split())
    if len(one_line_short) > 180:
        one_line_short = one_line_short[:177] + "..."

    notes = []
    if event.source_mtime:
        notes.append(f"source_mtime={event.source_mtime}")
    if event.container_path:
        notes.append(f"container={event.container_path}")

    extra = {
        "artifact": event.artifact,
        "event_type": event.event_type,
        "command_index": event.command_index,
        "line_number": event.line_number,
        "timestamp_raw": event.timestamp_raw,
        "metadata_json": _metadata_json(event.metadata, metadata_cache),
    }

    return {
        "date": date_value,
        "time": time_value,
        "timezone": event.timezone,
        "MACB": "MACB",
        "source": "LOG",
        "sourcetype": "PowerShell",
        "type": event.event_type,
        "user": event.user or "",
        "host": event.machine or "",
        "short": one_line_short,
        "desc": _space_multiline(short) or "",
        "version": "2",
        "filename": event.source_path,
        "inode": "",
        "notes": "; ".join(notes),
        "format": "powerscript_parser",
        "extra": json.dumps(extra, ensure_ascii=False, separators=(",", ":")),
    }


def _to_csv_row(event: Event) -> dict[str, str | int | None]:
    metadata = event.metadata
    decoded = _decoded_command_fields(metadata)
    row: dict[str, str | int | None] = {
        "artifact": event.artifact,
        "event_type": event.event_type,
        "timestamp": event.timestamp,
        "timestamp_raw": event.timestamp_raw,
        "timezone": event.timezone,
        "user": event.user,
        "run_as_user": event.run_as_user,
        "is_impersonated": _is_impersonated(event.user, event.run_as_user),
        "machine": event.machine,
        "host_application": _redact_host_encoded_command(event.host),
        "process_id": metadata.get("process_id"),
        "ps_version": metadata.get("ps_version"),
        "command_index": event.command_index,
        "line_number": event.line_number,
        "raw_block": _space_multiline(event.raw_block),
        "encoded_command": decoded["encoded_command"],
        "decoded_command": _space_multiline(decoded["decoded_command"]),
        "decoded_command_status": decoded["decoded_command_status"],
        "decoded_command_depth": decoded["decoded_command_depth"],
        "decoded_command_source": decoded["decoded_command_source"],
        "source_path": event.source_path,
        "container_path": event.container_path,
        "source_mtime": event.source_mtime,
    }
    return {column: row.get(column) for column in CSV_COLUMNS}


def _decoded_command_fields(metadata: dict[str, Any]) -> dict[str, str | None]:
    for source, prefix in (("command", "command_"), ("host_application", "host_")):
        encoded = _string_or_none(metadata.get(f"{prefix}encoded_command"))
        status = _string_or_none(metadata.get(f"{prefix}decoded_command_status"))
        if not encoded and status in {None, "not_present"}:
            continue
        return {
            "encoded_command": encoded,
            "decoded_command": _string_or_none(metadata.get(f"{prefix}decoded_command")),
            "decoded_command_status": status,
            "decoded_command_depth": _string_or_none(metadata.get(f"{prefix}decoded_command_depth")),
            "decoded_command_source": source,
        }
    return {
        "encoded_command": None,
        "decoded_command": None,
        "decoded_command_status": "not_present",
        "decoded_command_depth": "0",
        "decoded_command_source": None,
    }


def _redact_host_encoded_command(host_application: str | None) -> str | None:
    if host_application is None:
        return None
    return ENCODED_COMMAND_VALUE_RE.sub(r"\1 <encoded_command>", host_application)


def _is_impersonated(user: str | None, run_as_user: str | None) -> str:
    if not user or not run_as_user:
        return "false"
    return str(user.strip().casefold() != run_as_user.strip().casefold()).lower()


def _space_multiline(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    return "\n\n".join(normalized.split("\n"))


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _metadata_json(metadata: Any, cache: dict[int, str]) -> str:
    cache_key = id(metadata)
    if cache_key not in cache:
        cache[cache_key] = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))
    return cache[cache_key]
