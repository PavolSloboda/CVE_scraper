"""Map CLI/component names to queries; match CVE affected[] version data."""

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
    stream: tuple[int, ...] | None = None  # e.g. (11, 8) for 11.8.x
    fix_version: tuple[int, ...] | None = None  # e.g. (11, 8, 6) for fixed-in query


def parse_version_tuple(version: str) -> tuple[int, ...] | None:
    # Numeric tuple for comparisons; returns None for n/a, all, unparseable text.
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


def split_component_and_stream(component: str) -> tuple[str, str | None]:
    # Product names may include hyphens (spring-boot). Stream is a trailing x.y[.z].
    # log4j has no trailing numeric stream; apache-tomcat9.0 -> apache-tomcat + 9.0.
    text = component.strip()
    match = re.match(r"^(.+?)(\d[\d.]*)$", text)
    if not match:
        return text.lower(), None
    product = match.group(1).rstrip("-_.")
    stream_text = match.group(2)
    if not product:
        return text.lower(), None
    return product.lower(), stream_text


def parse_component_name(component: str) -> MatchQuery:
    # our_components line, e.g. mariadb11.8 -> product mariadb, stream 11.8.
    product, stream_text = split_component_and_stream(component)
    if stream_text:
        stream = parse_version_tuple(stream_text)
        return MatchQuery(
            product=product,
            mode=VersionMode.STREAM,
            stream=stream,
        )
    return MatchQuery(product=product, mode=VersionMode.ANY)


def parse_manual_version(version: str) -> tuple[VersionMode, tuple[int, ...] | None]:
    # Three-part -v is a fix query; one/two-part is a stream; all/* skips version filter.
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
    # Open-ended range: only the stream branch (not older lines like 10.6.x for 11.8).
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


_INVALID_IDENTIFIERS = frozenset({"", "n/a", "na", "unknown"})


def normalize_identifier(name: str) -> str | None:
    # Compare vendor/product names without case, spaces, or punctuation.
    if not name:
        return None
    cleaned = name.strip().lower()
    if cleaned in _INVALID_IDENTIFIERS:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "", cleaned)
    return normalized or None


def _parse_cpe23_vendor_product(cpe: str) -> tuple[str | None, str | None]:
    # cpe:2.3:part:vendor:product:version:...
    parts = cpe.strip().split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None, None
    vendor = parts[3] if parts[3] not in ("*", "-") else ""
    product = parts[4] if parts[4] not in ("*", "-") else ""
    return normalize_identifier(vendor), normalize_identifier(product)


def _parse_purl_identifier(package_url: str) -> str | None:
    # pkg:type/namespace/name@version or pkg:type/name@version
    match = re.match(
        r"pkg:[^/]+/(?:[^/@]+/)*([^/@]+)(?:@|$)",
        package_url.strip(),
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    return normalize_identifier(match.group(1))


def iter_product_identifiers(affected: dict):
    """Yield normalized names from structured CVE affected fields (not free-text grep)."""
    for field in ("vendor", "product", "packageName"):
        normalized = normalize_identifier(str(affected.get(field) or ""))
        if normalized:
            yield normalized

    package_url = affected.get("packageURL") or affected.get("packageUrl")
    if package_url:
        purl_name = _parse_purl_identifier(str(package_url))
        if purl_name:
            yield purl_name

    for cpe in affected.get("cpes") or []:
        cpe_vendor, cpe_product = _parse_cpe23_vendor_product(str(cpe))
        if cpe_vendor:
            yield cpe_vendor
        if cpe_product:
            yield cpe_product


def product_matches_target(affected: dict, target: str) -> bool:
    # Match -p against vendor, product, packageName, CPE, or PURL — exact token after normalize.
    target_norm = normalize_identifier(target)
    if not target_norm:
        return False
    return target_norm in set(iter_product_identifiers(affected))


_DESCRIPTION_PATTERN_CACHE: dict[tuple[str, tuple[int, ...]], tuple[re.Pattern[str], ...]] = {}


def _description_patterns(query: MatchQuery) -> tuple[re.Pattern[str], ...]:
    if query.stream is None:
        return ()
    cache_key = (query.product, query.stream)
    cached = _DESCRIPTION_PATTERN_CACHE.get(cache_key)
    if cached is not None:
        return cached
    stream_re = r"\.".join(str(part) for part in query.stream)
    product_re = re.escape(query.product)
    compiled = (
        re.compile(
            rf"\b{stream_re}\.x\b.*?\bbefore\s+({stream_re}\.\d+)",
            flags=re.IGNORECASE,
        ),
        re.compile(rf"\bbefore\s+({stream_re}\.\d+)", flags=re.IGNORECASE),
        re.compile(
            rf"\bfixed in\s+{product_re}\s+({stream_re}\.\d+)",
            flags=re.IGNORECASE,
        ),
    )
    _DESCRIPTION_PATTERN_CACHE[cache_key] = compiled
    return compiled


def extract_fix_labels_from_descriptions(data: dict, query: MatchQuery) -> set[str]:
    # Fallback when version[] lacks lessThan, e.g. "before 11.8.6" in prose.
    patterns = _description_patterns(query)
    if not patterns:
        return set()
    labels: set[str] = set()
    containers = data.get("containers") or {}
    for description in (containers.get("cna") or {}).get("descriptions") or []:
        text = description.get("value") or ""
        for pattern in patterns:
            for match in pattern.finditer(text):
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
    # Fix version = exclusive upper bound on the stream (lessThan on 11.8.x).
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
