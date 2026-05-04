from __future__ import annotations

import zipfile
from datetime import datetime
from pathlib import Path

from .models import SourceFile, path_label

TRANSCRIPT_PREFIX = "powershell_transcript."
HISTORY_NAME = "consolehost_history.txt"


def is_transcript_name(name: str) -> bool:
    lower = Path(name).name.lower()
    return lower.startswith(TRANSCRIPT_PREFIX) and lower.endswith(".txt")


def is_history_name(name: str) -> bool:
    return Path(name).name.lower() == HISTORY_NAME


def artifact_matches(name: str, artifact: str) -> bool:
    if artifact == "all":
        return is_transcript_name(name) or is_history_name(name)
    if artifact == "transcripts":
        return is_transcript_name(name)
    if artifact == "history":
        return is_history_name(name)
    return False


def default_input_paths() -> list[Path]:
    paths: list[Path] = []
    home = Path.home()
    paths.append(home / "Documents")
    paths.append(_history_path(home))

    for users_root in (Path("/Users"), Path("C:/Users")):
        if not users_root.exists():
            continue
        for profile in users_root.iterdir():
            if not profile.is_dir():
                continue
            paths.append(profile / "Documents")
            paths.append(_history_path(profile))

    paths.extend(
        [
            Path("/ProgramData/PowerShellTranscripts"),
            Path("C:/ProgramData/PowerShellTranscripts"),
            Path("ProgramData/PowerShellTranscripts"),
        ]
    )

    seen: set[str] = set()
    existing: list[Path] = []
    for path in paths:
        if not path.exists():
            continue
        key = str(path.resolve())
        if key not in seen:
            seen.add(key)
            existing.append(path)
    return existing


def collect_sources(directories: list[Path], files: list[Path], artifact: str) -> list[SourceFile]:
    sources: list[SourceFile] = []
    for path in directories:
        sources.extend(_collect_directory_input(path, artifact))
    for path in files:
        sources.extend(_collect_file_input(path, artifact))
    return sources


def _history_path(profile: Path) -> Path:
    return profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / HISTORY_NAME


def collect_default_sources(artifact: str) -> list[SourceFile]:
    directories: list[Path] = []
    files: list[Path] = []
    for path in default_input_paths():
        if path.is_dir():
            directories.append(path)
        elif path.is_file():
            files.append(path)
    return collect_sources(directories, files, artifact)


def _collect_directory_input(path: Path, artifact: str) -> list[SourceFile]:
    if path.is_file() and zipfile.is_zipfile(path):
        return _collect_zip(path, artifact)
    if path.is_file():
        return _collect_file_input(path, artifact)
    if not path.exists():
        raise FileNotFoundError(f"input directory not found: {path}")
    if not path.is_dir():
        raise ValueError(f"not a directory or zip file: {path}")

    return [
        _read_disk_file(file_path)
        for file_path in sorted(p for p in path.rglob("*") if p.is_file())
        if artifact_matches(file_path.name, artifact)
    ]


def _collect_file_input(path: Path, artifact: str) -> list[SourceFile]:
    if not path.exists():
        raise FileNotFoundError(f"input file not found: {path}")
    if not path.is_file():
        raise ValueError(f"not a file: {path}")
    if not artifact_matches(path.name, artifact):
        return []
    return [_read_disk_file(path)]


def _read_disk_file(path: Path) -> SourceFile:
    return SourceFile(
        display_path=path_label(path),
        name=path.name,
        text=_decode_bytes(path.read_bytes()),
        modified_time=datetime.fromtimestamp(path.stat().st_mtime).astimezone().isoformat(),
    )


def _collect_zip(path: Path, artifact: str) -> list[SourceFile]:
    sources: list[SourceFile] = []
    with zipfile.ZipFile(path) as archive:
        for info in sorted(archive.infolist(), key=lambda item: item.filename):
            if info.is_dir() or not artifact_matches(info.filename, artifact):
                continue
            data = archive.read(info)
            modified_time = _zip_time_to_iso(info)
            sources.append(
                SourceFile(
                    display_path=f"{path_label(path)}::{info.filename}",
                    name=Path(info.filename).name,
                    text=_decode_bytes(data),
                    container_path=path_label(path),
                    modified_time=modified_time,
                )
            )
    return sources


def _decode_bytes(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-8", "cp1252"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _zip_time_to_iso(info: zipfile.ZipInfo) -> str:
    return datetime(*info.date_time).isoformat()
