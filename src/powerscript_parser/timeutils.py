from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def filesystem_timestamp(now: datetime | None = None) -> str:
    value = now or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def parse_timezone(value: str) -> tuple[tzinfo, str]:
    label = value.strip() or "UTC"
    upper = label.upper()
    if upper in {"UTC", "Z"}:
        return timezone.utc, "UTC"
    if len(label) == 6 and label[0] in "+-" and label[3] == ":":
        sign = 1 if label[0] == "+" else -1
        hours = int(label[1:3])
        minutes = int(label[4:6])
        return timezone(sign * timedelta(hours=hours, minutes=minutes)), label
    try:
        return ZoneInfo(label), label
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown timezone: {value}") from exc


def parse_powershell_timestamp(value: str | None, timezone_name: str) -> str | None:
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    tzinfo, _ = parse_timezone(timezone_name)
    for fmt in ("%Y%m%d%H%M%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.strptime(raw, fmt)
            return _format_output_timestamp(parsed.replace(tzinfo=tzinfo))
        except ValueError:
            continue
    return None


def _format_output_timestamp(value: datetime) -> str:
    return f"{value:%Y-%m-%d %H:%M:%S}.{value.microsecond // 100:04d}"
