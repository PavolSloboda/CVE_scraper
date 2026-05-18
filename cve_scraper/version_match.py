import re
from dataclasses import dataclass
from enum import Enum


class VersionMode(Enum):
    ANY = "any"
    STREAM = "stream"
    FIX = "fix"


@dataclass(frozen=True)
class MatchQuery:
    product: str
    mode: VersionMode
    stream: tuple[int, ...] | None = None
    fix_version: tuple[int, ...] | None = None


def parse_version_tuple(version: str) -> tuple[int, ...] | None:
    if not version or version.lower() in ("n/a", "all", "unknown"):
        return None
    parts: list[int] = []
    for piece in re.split(r"[.\-_]", version.strip()):
        if not piece:
            continue
        if piece.isdigit():
            parts.append(int(piece))
        else:
            digits = "".join(ch for ch in piece if ch.isdigit())
            if not digits:
                return None
            parts.append(int(digits))
    return tuple(parts) if parts else None


def parse_component_name(component: str) -> MatchQuery:
    match = re.match(r"^([a-zA-Z_]+)([\d.]+)?$", component.strip())
    if not match:
        return MatchQuery(product=component.lower(), mode=VersionMode.ANY)
    product, stream_text = match.group(1), match.group(2)
    if stream_text:
        stream = parse_version_tuple(stream_text)
        return MatchQuery(
            product=product.lower(),
            mode=VersionMode.STREAM,
            stream=stream,
        )
    return MatchQuery(product=product.lower(), mode=VersionMode.ANY)


def parse_manual_version(version: str) -> tuple[VersionMode, tuple[int, ...] | None]:
    normalized = version.strip().lower()
    if normalized in ("all", "*"):
        return VersionMode.ANY, None
    version_tuple = parse_version_tuple(version)
    if version_tuple is None:
        return VersionMode.ANY, None
    if len(version_tuple) >= 3:
        return VersionMode.FIX, version_tuple
    return VersionMode.STREAM, version_tuple


def build_manual_query(package: str, version: str) -> MatchQuery:
    mode, version_tuple = parse_manual_version(version)
    if mode == VersionMode.ANY:
        return MatchQuery(product=package.lower(), mode=VersionMode.ANY)
    if mode == VersionMode.FIX:
        return MatchQuery(
            product=package.lower(),
            mode=VersionMode.FIX,
            fix_version=version_tuple,
        )
    return MatchQuery(
        product=package.lower(),
        mode=VersionMode.STREAM,
        stream=version_tuple,
    )


def _starts_with_stream(version: tuple[int, ...], stream: tuple[int, ...]) -> bool:
    if len(version) < len(stream):
        return False
    return version[: len(stream)] == stream


def _stream_bounds(stream: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    low = stream + (0,)
    high = stream + (999999,)
    return low, high


def _upper_bound(
    entry: dict,
) -> tuple[tuple[int, ...] | None, bool]:
    if "lessThan" in entry:
        bound = parse_version_tuple(str(entry["lessThan"]))
        return bound, False
    if "lessThanOrEqual" in entry:
        bound = parse_version_tuple(str(entry["lessThanOrEqual"]))
        return bound, True
    return None, False


def _range_overlaps_stream(
    lower: tuple[int, ...] | None,
    upper: tuple[int, ...] | None,
    upper_inclusive: bool,
    stream: tuple[int, ...],
) -> bool:
    stream_low, stream_high = _stream_bounds(stream)
    if lower is None:
        lower = (0,)
    if upper is None:
        return _starts_with_stream(lower, stream) or lower <= stream_high
    if not upper_inclusive:
        effective_upper = upper
    else:
        effective_upper = upper + (0,)
    return lower <= stream_high and effective_upper > stream_low


def _version_entry_matches_stream(entry: dict, stream: tuple[int, ...]) -> bool:
    status = entry.get("status", "affected")
    if status != "affected":
        return False
    lower = parse_version_tuple(str(entry.get("version", "")))
    upper, upper_inclusive = _upper_bound(entry)
    if lower is not None and _starts_with_stream(lower, stream):
        return True
    if upper is not None and _starts_with_stream(upper, stream):
        return True
    return _range_overlaps_stream(lower, upper, upper_inclusive, stream)


def _version_entry_matches_fix(entry: dict, fix_version: tuple[int, ...]) -> bool:
    fix_text = ".".join(str(part) for part in fix_version)
    for key in ("lessThan", "lessThanOrEqual"):
        if key not in entry:
            continue
        bound = parse_version_tuple(str(entry[key]))
        if bound == fix_version:
            return True
        if str(entry[key]).strip() == fix_text:
            return True
    if entry.get("status") == "unaffected":
        unaffected = parse_version_tuple(str(entry.get("version", "")))
        if unaffected == fix_version:
            return True
    return False


def affected_matches_query(affected: dict, query: MatchQuery) -> bool:
    product = affected.get("product", "")
    vendor = affected.get("vendor", "")
    target = query.product
    if target not in product.lower() and target not in vendor.lower():
        return False

    versions = affected.get("versions") or []
    if query.mode == VersionMode.ANY:
        if not versions:
            return affected.get("defaultStatus") == "affected"
        return any(v.get("status") == "affected" for v in versions)

    if query.mode == VersionMode.FIX:
        return any(
            _version_entry_matches_fix(version_entry, query.fix_version)
            for version_entry in versions
        )

    if query.stream is None:
        return False
    return any(
        _version_entry_matches_stream(version_entry, query.stream)
        for version_entry in versions
    )
