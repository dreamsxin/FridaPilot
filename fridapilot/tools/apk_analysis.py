"""APK/DEX Static Analysis - Android binary analysis without running the app.

Provides offline analysis of APK packages and DEX bytecode:
- APK structure extraction (AndroidManifest, resources, native libs)
- DEX header/class/method/string parsing
- Protection detection (root check, SSL pinning, obfuscation)
- Permission and component analysis

Pure Python — no external tools required (no jadx/apktool dependency).
No LLM dependency.
"""

from __future__ import annotations

import re
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Data Models ───────────────────────────────────────────────


@dataclass
class APKAnalysis:
    """Result of APK package analysis."""
    filepath: str
    package_name: str = ""
    version_name: str = ""
    version_code: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    dex_count: int = 0
    has_native_code: bool = False
    signing_info: dict[str, Any] = field(default_factory=dict)
    protections: list[dict[str, str]] = field(default_factory=list)


@dataclass
class DEXAnalysis:
    """Result of DEX file analysis."""
    filepath: str
    magic: str = ""
    version: str = ""
    checksum: int = 0
    file_size: int = 0
    class_count: int = 0
    method_count: int = 0
    string_count: int = 0
    classes: list[str] = field(default_factory=list)
    strings_sample: list[str] = field(default_factory=list)


# ── APK Analysis ──────────────────────────────────────────────


def analyze_apk(filepath: str | Path) -> APKAnalysis:
    """Analyze an APK package: manifest, permissions, components, native libs, protections.

    Args:
        filepath: Path to the .apk file.

    Returns:
        APKAnalysis with all extracted metadata.
    """
    filepath = Path(filepath)
    result = APKAnalysis(filepath=str(filepath))

    if not zipfile.is_zipfile(filepath):
        return result

    with zipfile.ZipFile(filepath, "r") as zf:
        names = zf.namelist()

        # Count DEX files
        dex_files = [n for n in names if n.endswith(".dex")]
        result.dex_count = len(dex_files)

        # Check for native libraries
        native_libs = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
        result.native_libs = native_libs
        result.has_native_code = len(native_libs) > 0

        # Parse AndroidManifest.xml (binary XML)
        if "AndroidManifest.xml" in names:
            manifest_data = zf.read("AndroidManifest.xml")
            _parse_binary_manifest(manifest_data, result)

        # Parse DEX files for strings (protection detection). Scanning only the
        # first DEX misses everything in a multi-dex app, which is most of them.
        all_strings: list[str] = []
        for name in dex_files:
            _dex, strings = _parse_dex_header(zf.read(name))
            all_strings.extend(strings)

        if all_strings:
            _detect_protections(all_strings, result)


        # Check signing
        cert_files = [n for n in names if n.startswith("META-INF/") and
                      (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC"))]
        result.signing_info = {
            "signed": len(cert_files) > 0,
            "v1": any(n == "META-INF/MANIFEST.MF" for n in names),
            "v2_v3": False,  # Would need APK Signing Block parsing
            "cert_files": cert_files,
        }

    return result


def _parse_binary_manifest(data: bytes, result: APKAnalysis) -> None:
    """Fill package/version/sdk/components from the binary AndroidManifest.xml.

    Reads the actual element and attribute records. The previous approach —
    classifying raw string-pool entries by substring ("Activity" in s) and taking
    the first string with two dots as the package name — cannot distinguish an
    attribute value from a resource name, so it reported library classes as the
    package and left versionName/versionCode/minSdk/targetSdk permanently empty.
    """
    elements = list(_iter_axml_elements(data))

    pkg = ""
    for tag, attrs in elements:
        if tag == "manifest":
            pkg = str(attrs.get("package", "") or "")
            result.package_name = pkg
            result.version_name = str(attrs.get("versionName", "") or "")
            result.version_code = _as_int(attrs.get("versionCode"))
        elif tag == "uses-sdk":
            result.min_sdk = _as_int(attrs.get("minSdkVersion"))
            result.target_sdk = _as_int(attrs.get("targetSdkVersion"))
        elif tag == "uses-permission":
            name = str(attrs.get("name", "") or "")
            if name:
                result.permissions.append(name)
        elif tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            name = _qualify(pkg, str(attrs.get("name", "") or ""))
            if not name:
                continue
            {"activity": result.activities, "activity-alias": result.activities,
             "service": result.services, "receiver": result.receivers,
             "provider": result.providers}[tag].append(name)

    if not elements:
        # Unparsable / non-standard AXML: recover permissions only, by exact prefix.
        for s in _parse_axml_string_pool(data):
            if s.startswith("android.permission."):
                result.permissions.append(s)


def _qualify(package: str, name: str) -> str:
    """Expand a relative component name (".MainActivity") against the package."""
    if not name:
        return ""
    if name.startswith("."):
        return package + name if package else name
    if "." not in name and package:
        return "%s.%s" % (package, name)
    return name


def _as_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return 0
    return 0


# Android binary XML (AXML) chunk types, from ResourceTypes.h
_CHUNK_STRING_POOL = 0x0001
_CHUNK_START_ELEMENT = 0x0102


def _parse_axml_string_pool(data: bytes) -> list[str]:
    """Return the AXML string pool as an index-addressable list ([] on failure)."""
    offset = 8  # skip the file header
    while offset + 8 <= len(data):
        try:
            chunk_type = struct.unpack_from("<H", data, offset)[0]
            chunk_size = struct.unpack_from("<I", data, offset + 4)[0]
        except struct.error:
            return []
        if chunk_size < 8:
            return []
        if chunk_type == _CHUNK_STRING_POOL:
            return _read_string_pool(data, offset)
        offset += chunk_size
    return []


def _read_string_pool(data: bytes, offset: int) -> list[str]:
    """Decode a ResStringPool chunk at ``offset`` into a list of strings."""
    strings: list[str] = []
    try:
        count = struct.unpack_from("<I", data, offset + 8)[0]
        flags = struct.unpack_from("<I", data, offset + 16)[0]
        strings_start = struct.unpack_from("<I", data, offset + 20)[0]
    except struct.error:
        return strings
    is_utf8 = (flags & (1 << 8)) != 0
    offsets_at = offset + 28
    data_at = offset + strings_start

    for i in range(min(count, 20000)):
        try:
            rel = struct.unpack_from("<I", data, offsets_at + i * 4)[0]
        except struct.error:
            break
        pos = data_at + rel
        if pos >= len(data):
            strings.append("")
            continue
        if is_utf8:
            # two length fields: UTF-16 length, then byte length (1-2 bytes each)
            b = data[pos]
            pos += 2 if b & 0x80 else 1
            if pos >= len(data):
                strings.append("")
                continue
            b = data[pos]
            if b & 0x80:
                if pos + 1 >= len(data):
                    strings.append("")
                    continue
                byte_len = ((b & 0x7F) << 8) | data[pos + 1]
                pos += 2
            else:
                byte_len = b
                pos += 1
            strings.append(data[pos:pos + byte_len].decode("utf-8", errors="replace"))
        else:
            if pos + 2 > len(data):
                strings.append("")
                continue
            char_len = struct.unpack_from("<H", data, pos)[0]
            if char_len & 0x8000:  # 32-bit length escape
                char_len = ((char_len & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos + 2)[0]
                pos += 4
            else:
                pos += 2
            strings.append(data[pos:pos + char_len * 2].decode("utf-16-le", errors="replace"))
    return strings


def _iter_axml_elements(data: bytes):
    """Yield (tag_name, {attribute_name: value}) for each AXML START_ELEMENT.

    Attribute values resolve to the raw string when present, otherwise to the typed
    value (int / bool / "@0x..." resource reference).
    """
    pool: list[str] = []
    offset = 8
    while offset + 8 <= len(data):
        try:
            chunk_type = struct.unpack_from("<H", data, offset)[0]
            header_size = struct.unpack_from("<H", data, offset + 2)[0]
            chunk_size = struct.unpack_from("<I", data, offset + 4)[0]
        except struct.error:
            return
        if chunk_size < 8 or offset + chunk_size > len(data):
            return

        if chunk_type == _CHUNK_STRING_POOL:
            pool = _read_string_pool(data, offset)
        elif chunk_type == _CHUNK_START_ELEMENT and pool:
            ext = offset + max(header_size, 16)
            try:
                name_idx = struct.unpack_from("<I", data, ext + 4)[0]
                attr_start = struct.unpack_from("<H", data, ext + 8)[0]
                attr_size = struct.unpack_from("<H", data, ext + 10)[0]
                attr_count = struct.unpack_from("<H", data, ext + 12)[0]
            except struct.error:
                return
            tag = pool[name_idx] if name_idx < len(pool) else ""
            attrs: dict[str, Any] = {}
            base = ext + attr_start
            stride = attr_size or 20
            for i in range(min(attr_count, 256)):
                at = base + i * stride
                if at + 20 > len(data):
                    break
                a_name = struct.unpack_from("<I", data, at + 4)[0]
                raw = struct.unpack_from("<I", data, at + 8)[0]
                dtype = data[at + 15]
                value_int = struct.unpack_from("<I", data, at + 16)[0]
                key = pool[a_name] if a_name < len(pool) else ""
                if raw != 0xFFFFFFFF and raw < len(pool):
                    value: Any = pool[raw]
                elif dtype in (0x10, 0x11):        # INT_DEC / INT_HEX
                    value = value_int
                elif dtype == 0x12:                # INT_BOOLEAN
                    value = bool(value_int)
                elif dtype == 0x01:                # REFERENCE
                    value = "@0x%08x" % value_int
                else:
                    value = value_int
                if key:
                    attrs[key] = value
            yield tag, attrs

        offset += chunk_size



# ── DEX Analysis ──────────────────────────────────────────────


def analyze_dex(filepath: str | Path) -> DEXAnalysis:
    """Analyze a DEX file: header, classes, methods, strings.

    Args:
        filepath: Path to the .dex file (or classes.dex extracted from APK).

    Returns:
        DEXAnalysis with extracted metadata.
    """
    filepath = Path(filepath)
    data = filepath.read_bytes()
    return _parse_dex_header(data, str(filepath))[0]


def _parse_dex_header(data: bytes, filepath: str = "") -> tuple[DEXAnalysis, list[str]]:
    """Parse a DEX header. Returns (analysis, all_extracted_strings).

    The full string list is returned separately from ``strings_sample`` so callers
    can run detection over everything while the reported sample stays small.
    """
    result = DEXAnalysis(filepath=filepath)

    if len(data) < 112:
        return result, []

    # DEX header
    magic = data[:8]
    if not magic[:4] == b"dex\n":
        return result, []


    result.magic = magic[:4].decode("ascii", errors="replace")
    result.version = magic[4:7].decode("ascii", errors="replace")
    result.checksum = struct.unpack_from("<I", data, 8)[0]
    result.file_size = struct.unpack_from("<I", data, 32)[0]

    # String IDs
    string_ids_size = struct.unpack_from("<I", data, 56)[0]
    string_ids_off = struct.unpack_from("<I", data, 60)[0]
    result.string_count = string_ids_size

    # Method IDs

    method_ids_size = struct.unpack_from("<I", data, 88)[0]
    result.method_count = method_ids_size

    # Class defs
    class_defs_size = struct.unpack_from("<I", data, 96)[0]
    result.class_count = class_defs_size

    # Extract strings. The ULEB128 prefix counts UTF-16 code units, not bytes, so
    # using it as a byte length truncates every string containing a non-ASCII
    # character. The data is NUL-terminated MUTF-8 — read up to the terminator.
    strings: list[str] = []
    for i in range(min(string_ids_size, 20000)):
        try:
            str_off_ptr = string_ids_off + i * 4
            if str_off_ptr + 4 > len(data):
                break
            str_data_off = struct.unpack_from("<I", data, str_off_ptr)[0]
            if str_data_off >= len(data):
                continue
            pos = str_data_off
            while pos < len(data) and (data[pos] & 0x80):  # skip ULEB128 prefix
                pos += 1
            pos += 1
            end = data.find(b"\x00", pos, pos + 8192)
            if end < 0:
                continue
            s = data[pos:end].decode("utf-8", errors="replace")
            if len(s) >= 3:
                strings.append(s)
        except Exception:
            continue

    result.strings_sample = strings[:500]

    # Extract class names from strings (Lcom/example/...)
    result.classes = [s for s in strings if s.startswith("L") and "/" in s and s.endswith(";")][:200]

    return result, strings



# ── Protection Detection ──────────────────────────────────────

_PROTECTION_INDICATORS: dict[str, list[tuple[str, str]]] = {
    "root_detection": [
        ("su", "Binary 'su' check"),
        ("Superuser.apk", "Superuser app detection"),
        ("/system/app/Superuser", "Superuser path check"),
        ("com.noshufou.android.su", "su management app"),
        ("com.thirdparty.superuser", "Third-party su"),
        ("eu.chainfire.supersu", "SuperSU detection"),
        ("com.topjohnwu.magisk", "Magisk detection"),
        ("isRooted", "Root check method"),
        ("RootDetection", "Root detection class"),
        ("isDeviceRooted", "Device root check"),
    ],
    "ssl_pinning": [
        ("CertificatePinner", "OkHttp certificate pinner"),
        ("X509TrustManager", "Custom trust manager"),
        ("SSLPinning", "SSL pinning class"),
        ("TrustManagerFactory", "Trust manager factory"),
        ("checkServerTrusted", "Server cert validation"),
        ("NetworkSecurityConfig", "Network security config"),
    ],
    "frida_detection": [
        ("frida", "Frida string reference"),
        ("27042", "Frida default port"),
        ("xposed", "Xposed framework"),
        ("substrate", "Cydia Substrate"),
    ],

    "obfuscation": [
        ("proguard", "ProGuard obfuscation"),
        ("DexGuard", "DexGuard protection"),
        ("ijiami", "Ijiami packer"),
        ("bangcle", "Bangcle protection"),
        ("secneo", "SecNeo protection"),
        ("tencent", "Tencent Legu"),
        ("qihoo", "360 protection"),
    ],
    "emulator_detection": [
        ("generic", "Generic emulator check"),
        ("goldfish", "Emulator hardware"),
        ("sdk_gphone", "SDK phone check"),
        ("isEmulator", "Emulator detection method"),
        ("Build.FINGERPRINT", "Build fingerprint check"),
    ],
}

_PATTERN_CACHE: dict[str, Any] = {}



def _indicator_match(strings: list[str], keyword: str) -> str | None:
    """First string containing ``keyword`` as a standalone token, else None.

    Matching substrings against one concatenated blob (the previous approach) makes
    short indicators worthless: "su" hits "issue" and "consumer", "generic" hits
    "generic_thing", so every APK came back root- and emulator-aware. Requiring
    non-identifier characters on both sides keeps "/system/xbin/su",
    "Build.FINGERPRINT" and "com.topjohnwu.magisk" while dropping those.
    """
    pat = _PATTERN_CACHE.get(keyword)
    if pat is None:
        pat = re.compile(r"(?<![A-Za-z0-9_])%s(?![A-Za-z0-9_])" % re.escape(keyword),
                         re.IGNORECASE)
        _PATTERN_CACHE[keyword] = pat
    for s in strings:
        if pat.search(s):
            return s
    return None


def _detect_protections(strings: list[str], result: APKAnalysis) -> None:
    """Detect security protections from DEX strings."""
    for category, indicators in _PROTECTION_INDICATORS.items():
        for keyword, description in indicators:
            match = _indicator_match(strings, keyword)
            if match is not None:
                result.protections.append({
                    "category": category,
                    "indicator": keyword,
                    "description": description,
                    "match": match[:160],
                })



def detect_protections(filepath: str | Path) -> list[dict[str, str]]:
    """Standalone protection detection for an APK file.

    Args:
        filepath: Path to the .apk file.

    Returns:
        List of detected protection indicators.
    """
    result = analyze_apk(filepath)
    return result.protections
