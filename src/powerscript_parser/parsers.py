from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable

from .models import Event, SourceFile
from .timeutils import parse_powershell_timestamp

HEADER_KEYS = {
    "Start time": "session_start_time_raw",
    "Username": "username",
    "RunAs User": "run_as_user",
    "Configuration Name": "configuration_name",
    "Machine": "machine",
    "Host Application": "host_application",
    "Process ID": "process_id",
    "PSVersion": "ps_version",
    "PSEdition": "ps_edition",
    "PSCompatibleVersions": "ps_compatible_versions",
    "BuildVersion": "build_version",
    "CLRVersion": "clr_version",
    "WSManStackVersion": "wsman_stack_version",
    "PSRemotingProtocolVersion": "ps_remoting_protocol_version",
    "SerializationVersion": "serialization_version",
    "End time": "session_end_time_raw",
}

ENCODED_COMMAND_RE = re.compile(r"(?i)(?:-|/)encodedcommand\s+([A-Za-z0-9+/=]+)|(?:-|/)enc\s+([A-Za-z0-9+/=]+)")
TRANSCRIPT_START = "Windows PowerShell transcript start"
TRANSCRIPT_END = "Windows PowerShell transcript end"
COMMAND_START = "Command start time:"
MAX_DECODE_DEPTH = 8
Metadata = dict[str, str | None]


def parse_sources(sources: Iterable[SourceFile], artifact: str, input_timezone: str) -> list[Event]:
    events: list[Event] = []
    for source in sources:
        lower = source.name.lower()
        if artifact in {"all", "transcripts"} and lower.startswith("powershell_transcript.") and lower.endswith(".txt"):
            events.extend(parse_transcript(source, input_timezone))
        elif artifact in {"all", "history"} and lower == "consolehost_history.txt":
            events.extend(parse_history(source, input_timezone))
    return events


def parse_transcript(source: SourceFile, input_timezone: str) -> list[Event]:
    text = source.text.replace("\r\n", "\n").replace("\r", "\n")
    segments = _transcript_segments(text)
    events: list[Event] = []
    for segment_start_line, segment in segments:
        metadata = _parse_header_metadata(segment)
        metadata.update(_decode_encoded_commands(metadata.get("host_application"), "host_"))
        metadata["session_start_time"] = parse_powershell_timestamp(
            metadata.get("session_start_time_raw"),
            input_timezone,
        )
        metadata["session_end_time"] = parse_powershell_timestamp(
            metadata.get("session_end_time_raw"),
            input_timezone,
        )
        metadata["source_name"] = source.name

        command_blocks = _command_blocks(segment, segment_start_line)
        for index, (timestamp_raw, line_number, block_lines) in enumerate(command_blocks, start=1):
            raw_block = "\n".join(block_lines).strip()
            command_text = _clean_command_text(block_lines)
            event_metadata: Metadata = dict(metadata)
            event_metadata.update(_decode_encoded_commands(command_text, "command_"))
            events.append(
                Event(
                    artifact="transcript",
                    event_type="powershell_command",
                    source_path=source.display_path,
                    container_path=source.container_path,
                    timestamp_raw=timestamp_raw,
                    timestamp=parse_powershell_timestamp(timestamp_raw, input_timezone),
                    timezone=input_timezone,
                    user=metadata.get("username"),
                    run_as_user=metadata.get("run_as_user"),
                    host=metadata.get("host_application"),
                    machine=metadata.get("machine"),
                    command_index=index,
                    line_number=line_number,
                    command_text=command_text,
                    raw_block=raw_block,
                    source_mtime=source.modified_time,
                    metadata=event_metadata,
                )
            )
    return events


def parse_history(source: SourceFile, input_timezone: str) -> list[Event]:
    events: list[Event] = []
    for line_number, line in enumerate(source.text.splitlines(), start=1):
        command = line.strip()
        if not command:
            continue
        events.append(
            Event(
                artifact="history",
                event_type="psreadline_history",
                source_path=source.display_path,
                container_path=source.container_path,
                timezone=input_timezone,
                command_text=command,
                raw_block=line,
                line_number=line_number,
                source_mtime=source.modified_time,
                metadata={"source_name": source.name},
            )
        )
    return events


def _transcript_segments(text: str) -> list[tuple[int, list[str]]]:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if TRANSCRIPT_START in line]
    if not starts:
        return [(1, lines)] if lines else []
    segments: list[tuple[int, list[str]]] = []
    for offset, start in enumerate(starts):
        end = starts[offset + 1] if offset + 1 < len(starts) else len(lines)
        segments.append((start + 1, lines[start:end]))
    return segments


def _parse_header_metadata(lines: list[str]) -> Metadata:
    metadata: Metadata = {}
    for line in lines:
        if COMMAND_START in line:
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in HEADER_KEYS:
            metadata[HEADER_KEYS[key]] = value.strip()
    return metadata


def _command_blocks(lines: list[str], start_line_number: int) -> list[tuple[str, int, list[str]]]:
    blocks: list[tuple[str, int, list[str]]] = []
    current_time: str | None = None
    current_start_line: int | None = None
    current_lines: list[str] = []

    for line_number, line in enumerate(lines, start=start_line_number):
        if COMMAND_START in line:
            if current_time is not None and current_start_line is not None:
                blocks.append((current_time, current_start_line, _trim_block(current_lines)))
            current_time = line.split(COMMAND_START, 1)[1].strip()
            current_start_line = line_number
            current_lines = []
            continue
        if current_time is None:
            continue
        if TRANSCRIPT_END in line:
            if current_start_line is not None:
                blocks.append((current_time, current_start_line, _trim_block(current_lines)))
            current_time = None
            current_start_line = None
            current_lines = []
            continue
        current_lines.append(line)

    if current_time is not None and current_start_line is not None:
        blocks.append((current_time, current_start_line, _trim_block(current_lines)))
    return blocks


def _trim_block(lines: list[str]) -> list[str]:
    start = 0
    end = len(lines)
    while start < end and _is_noise_line(lines[start]):
        start += 1
    while end > start and _is_noise_line(lines[end - 1]):
        end -= 1
    return lines[start:end]


def _is_noise_line(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped == "**********************"


def _clean_command_text(lines: list[str]) -> str:
    cleaned: list[str] = []
    for line in _trim_block(lines):
        if _is_noise_line(line):
            continue
        if line.startswith("PS>"):
            cleaned.append(line[3:].lstrip())
        elif line.startswith(">>"):
            cleaned.append(line[2:].lstrip())
        else:
            cleaned.append(line)
    return "\n".join(cleaned).strip()


def _decode_encoded_commands(text: str | None, prefix: str) -> Metadata:
    metadata: Metadata = {
        f"{prefix}encoded_command": None,
        f"{prefix}decoded_command": None,
        f"{prefix}decoded_command_status": "not_present",
        f"{prefix}decoded_command_depth": "0",
        f"{prefix}decoded_command_chain": "[]",
    }
    if not text:
        return metadata

    current = text
    chain: list[dict[str, str | int | None]] = []
    status = "not_present"
    for depth in range(1, MAX_DECODE_DEPTH + 1):
        match = ENCODED_COMMAND_RE.search(current)
        if not match:
            break
        encoded = match.group(1) or match.group(2)
        decoded, status = _decode_base64_command(encoded)
        chain.append(
            {
                "depth": depth,
                "encoded_command": encoded,
                "decoded_command": decoded,
                "decoded_command_status": status,
            }
        )
        if decoded is None:
            break
        current = decoded

    if chain:
        metadata[f"{prefix}encoded_command"] = str(chain[0]["encoded_command"])
        last_decoded = chain[-1]["decoded_command"]
        metadata[f"{prefix}decoded_command"] = str(last_decoded) if last_decoded else None
        metadata[f"{prefix}decoded_command_status"] = status
        metadata[f"{prefix}decoded_command_depth"] = str(len(chain))
        metadata[f"{prefix}decoded_command_chain"] = json.dumps(chain, ensure_ascii=False, separators=(",", ":"))
    return metadata


def _decode_base64_command(encoded: str) -> tuple[str | None, str]:
    try:
        data = base64.b64decode(encoded, validate=True)
    except ValueError:
        return None, "invalid_base64"
    for encoding in ("utf-16-le", "utf-8-sig", "utf-8"):
        try:
            return data.decode(encoding), f"decoded_{encoding}"
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "decoded_with_replacement"
