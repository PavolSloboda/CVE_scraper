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


def _parse_inline_range_bounds(
    version_text: str,
) -> tuple[tuple[int, ...] | None, tuple[int, ...] | None, str | None, bool]:
    text = version_text.strip()
    upper_label = None
    upper_inclusive = False
    upper = None
    lower = None

    upper_match = re.search(r"<\s*(=)?\s*([\d.]+)", text)
    if upper_match:
        upper_inclusive = upper_match.group(1) == "="
        upper_label = upper_match.group(2).strip()
        upper = parse_version_tuple(upper_label)

    lower_match = re.search(r">=\s*([\d.]+)", text)
    if lower_match:
        lower = parse_version_tuple(lower_match.group(1).strip())

    if upper is None and lower is None:
        lower = parse_version_tuple(text)

    return lower, upper, upper_label, upper_inclusive


def _upper_bound(
    entry: dict,
) -> tuple[tuple[int, ...] | None, bool]:
    if "lessThan" in entry:
        bound = parse_version_tuple(str(entry["lessThan"]))
        return bound, False
    if "lessThanOrEqual" in entry:
        bound = parse_version_tuple(str(entry["lessThanOrEqual"]))
        return bound, True

    version_text = str(entry.get("version", ""))
    if "<" in version_text:
        _, upper, _, upper_inclusive = _parse_inline_range_bounds(version_text)
        return upper, upper_inclusive
    return None, False


def _range_overlaps_stream(
    lower: tuple[int, ...] | None,
    upper: tuple[int, ...] | None,
    upper_inclusive: bool,
    stream: tuple[int, ...],
) -> bool:
    stream_low, stream_high = _stream_bounds(stream)
    if upper is None:
        return lower is not None and _starts_with_stream(lower, stream)
    if lower is None:
        lower = (0,)
    if not upper_inclusive:
        effective_upper = upper
    else:
        effective_upper = upper + (0,)
    return lower <= stream_high and effective_upper > stream_low


def _version_entry_bounds(
    entry: dict,
) -> tuple[tuple[int, ...] | None, tuple[int, ...] | None, str | None, bool]:
    if "lessThan" in entry:
        upper = parse_version_tuple(str(entry["lessThan"]))
        lower = parse_version_tuple(str(entry.get("version", "")))
        return lower, upper, str(entry["lessThan"]).strip(), False
    if "lessThanOrEqual" in entry:
        upper = parse_version_tuple(str(entry["lessThanOrEqual"]))
        lower = parse_version_tuple(str(entry.get("version", "")))
        return lower, upper, str(entry["lessThanOrEqual"]).strip(), True

    version_text = str(entry.get("version", ""))
    if "<" in version_text or ">=" in version_text:
        return _parse_inline_range_bounds(version_text)

    lower = parse_version_tuple(version_text)
    return lower, None, None, False


def _version_entry_matches_stream(entry: dict, stream: tuple[int, ...]) -> bool:
    status = entry.get("status", "affected")
    if status != "affected":
        return False
    lower, upper, _, upper_inclusive = _version_entry_bounds(entry)
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


_NON_DATABASE_MARKERS = (
    "node module",
    "node.js",
    "apb",
    "openshift",
    "ansible",
    "connector",
    "docker",
    "helm",
    "chart",
    "binding",
    "mariadb-apb",
)


def product_matches_target(affected: dict, target: str) -> bool:
    product = (affected.get("product") or "").lower().strip()
    vendor = (affected.get("vendor") or "").lower().strip()
    if product in ("n/a", "") and vendor in ("n/a", ""):
        return False

    haystack = f"{vendor} {product}"
    if any(marker in haystack for marker in _NON_DATABASE_MARKERS):
        return False

    for cpe in affected.get("cpes") or []:
        cpe_lower = cpe.lower()
        if any(marker in cpe_lower for marker in ("node.js", "apb", "node_module")):
            return False

    if target == "mariadb":
        if product in ("mariadb", "server") and (
            "mariadb" in vendor or vendor in ("n/a", "")
        ):
            return True
        return vendor == "mariadb" and product == "mariadb"

    return target in product or target in vendor


def extract_fix_labels_from_descriptions(
    data: dict, stream: tuple[int, ...]
) -> set[str]:
    stream_re = r"\.".join(str(part) for part in stream)
    labels: set[str] = set()
    containers = data.get("containers") or {}
    texts = []
    for description in (containers.get("cna") or {}).get("descriptions") or []:
        texts.append(description.get("value") or "")
    patterns = (
        rf"\b{stream_re}\.x\b.*?\bbefore\s+({stream_re}\.\d+)",
        rf"\bbefore\s+({stream_re}\.\d+)",
        rf"\bfixed in\s+[Mm]ariaDB\s+({stream_re}\.\d+)",
    )
    for text in texts:
        for pattern in patterns:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                labels.add(match.group(1))
    return labels


def format_version_label(version_tuple: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in version_tuple)


def _fix_label_from_entry(entry: dict) -> str | None:
    if "lessThan" in entry:
        return str(entry["lessThan"]).strip()
    if "lessThanOrEqual" in entry:
        return str(entry["lessThanOrEqual"]).strip()
    version_text = str(entry.get("version", "")).strip()
    fixed_in = re.search(r"fixed in\s+([\d.]+)", version_text, flags=re.IGNORECASE)
    if fixed_in:
        return fixed_in.group(1)
    return None


def _collect_stream_fix_labels(entry: dict, stream: tuple[int, ...]) -> set[str]:
    if entry.get("status", "affected") != "affected":
        return set()
    if not _version_entry_matches_stream(entry, stream):
        return set()
    _, upper, upper_label, _ = _version_entry_bounds(entry)
    if upper is None or not _starts_with_stream(upper, stream):
        return set()
    if upper_label:
        return {upper_label}
    label = _fix_label_from_entry(entry)
    if label:
        return {label}
    return {format_version_label(upper)}


def _collect_any_fix_labels(entry: dict) -> set[str]:
    if entry.get("status", "affected") != "affected":
        return set()
    label = _fix_label_from_entry(entry)
    if label:
        return {label}
    _, _, upper_label, _ = _version_entry_bounds(entry)
    return {upper_label} if upper_label else set()


def extract_fix_versions(affected: dict, query: MatchQuery) -> set[str]:
    if not product_matches_target(affected, query.product):
        return set()

    versions = affected.get("versions") or []
    labels: set[str] = set()

    if query.mode == VersionMode.FIX:
        if query.fix_version and any(
            _version_entry_matches_fix(version_entry, query.fix_version)
            for version_entry in versions
        ):
            labels.add(format_version_label(query.fix_version))
        return labels

    if query.mode == VersionMode.STREAM and query.stream is not None:
        for version_entry in versions:
            labels |= _collect_stream_fix_labels(version_entry, query.stream)
        return labels

    if query.mode == VersionMode.ANY:
        for version_entry in versions:
            labels |= _collect_any_fix_labels(version_entry)
        return labels

    return labels


def version_sort_key(version_label: str):
    if version_label == "unknown":
        return (999999,)
    parsed = parse_version_tuple(version_label)
    return parsed if parsed is not None else (999998,)


def affected_matches_query(affected: dict, query: MatchQuery) -> bool:
    if not product_matches_target(affected, query.product):
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
