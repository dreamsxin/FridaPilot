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

        # Parse first DEX for strings (protection detection)
        if dex_files:
            dex_data = zf.read(dex_files[0])
            dex = _parse_dex_header(dex_data)
            _detect_protections(dex.strings_sample, result)

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
    """Extract info from Android binary XML manifest using string table extraction."""
    # Binary XML is complex; extract strings from the string table as a pragmatic approach
    strings = _extract_binary_xml_strings(data)

    for s in strings:
        if s.startswith("android.permission."):
            result.permissions.append(s)
        elif "Activity" in s and "." in s and not s.startswith("android."):
            result.activities.append(s)
        elif "Service" in s and "." in s and not s.startswith("android."):
            result.services.append(s)
        elif "Receiver" in s and "." in s and not s.startswith("android."):
            result.receivers.append(s)
        elif "Provider" in s and "." in s and not s.startswith("android."):
            result.providers.append(s)

    # Try to extract package name (usually first non-android string with dots)
    for s in strings:
        if "." in s and not s.startswith("android.") and not s.startswith("http") \
           and not s.endswith(".xml") and s.count(".") >= 2 and len(s) < 100:
            result.package_name = s
            break


def _extract_binary_xml_strings(data: bytes) -> list[str]:
    """Extract string table from Android binary XML format."""
    strings: list[str] = []
    if len(data) < 16:
        return strings

    # Binary XML header: magic (0x00080003), file_size, string_pool_offset...
    # String pool starts after the header, with count at offset 8 of the pool
    try:
        # Find string pool chunk (type 0x0001)
        offset = 8  # Skip file header
        while offset + 8 < len(data):
            chunk_type = struct.unpack_from("<H", data, offset)[0]
            chunk_size = struct.unpack_from("<I", data, offset + 4)[0]
            if chunk_size < 8:
                break

            if chunk_type == 0x0001:  # String pool
                str_count = struct.unpack_from("<I", data, offset + 8)[0]
                flags = struct.unpack_from("<I", data, offset + 16)[0]
                is_utf8 = (flags & (1 << 8)) != 0
                str_start = struct.unpack_from("<I", data, offset + 20)[0]

                offsets_start = offset + 28
                data_start = offset + str_start

                for i in range(min(str_count, 2000)):
                    str_off = struct.unpack_from("<I", data, offsets_start + i * 4)[0]
                    abs_off = data_start + str_off

                    if abs_off >= len(data):
                        continue

                    if is_utf8:
                        # UTF-8: skip char count (1-2 bytes), then byte count (1-2 bytes)
                        pos = abs_off
                        if pos < len(data):
                            b = data[pos]
                            pos += 2 if b & 0x80 else 1
                        if pos < len(data):
                            b = data[pos]
                            byte_len = ((b & 0x7F) << 8 | data[pos + 1]) if b & 0x80 else b
                            pos += 2 if b & 0x80 else 1
                        else:
                            continue
                        if pos + byte_len <= len(data):
                            try:
                                s = data[pos:pos + byte_len].decode("utf-8", errors="replace")
                                if s and len(s) > 1:
                                    strings.append(s)
                            except Exception:
                                pass
                    else:
                        # UTF-16
                        if abs_off + 2 > len(data):
                            continue
                        char_len = struct.unpack_from("<H", data, abs_off)[0]
                        str_data = data[abs_off + 2:abs_off + 2 + char_len * 2]
                        try:
                            s = str_data.decode("utf-16-le", errors="replace")
                            if s and len(s) > 1:
                                strings.append(s)
                        except Exception:
                            pass
                break

            offset += chunk_size
    except Exception:
        pass

    return strings


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
    return _parse_dex_header(data, str(filepath))


def _parse_dex_header(data: bytes, filepath: str = "") -> DEXAnalysis:
    """Parse DEX file header and extract metadata."""
    result = DEXAnalysis(filepath=filepath)

    if len(data) < 112:
        return result

    # DEX header
    magic = data[:8]
    if not magic[:4] == b"dex\n":
        return result

    result.magic = magic[:4].decode("ascii", errors="replace")
    result.version = magic[4:7].decode("ascii", errors="replace")
    result.checksum = struct.unpack_from("<I", data, 8)[0]
    result.file_size = struct.unpack_from("<I", data, 32)[0]

    # String IDs
    string_ids_size = struct.unpack_from("<I", data, 56)[0]
    string_ids_off = struct.unpack_from("<I", data, 60)[0]
    result.string_count = string_ids_size

    # Type IDs
    type_ids_size = struct.unpack_from("<I", data, 64)[0]

    # Method IDs
    method_ids_size = struct.unpack_from("<I", data, 88)[0]
    result.method_count = method_ids_size

    # Class defs
    class_defs_size = struct.unpack_from("<I", data, 96)[0]
    result.class_count = class_defs_size

    # Extract strings (sample)
    strings: list[str] = []
    for i in range(min(string_ids_size, 5000)):
        try:
            str_off_ptr = string_ids_off + i * 4
            if str_off_ptr + 4 > len(data):
                break
            str_data_off = struct.unpack_from("<I", data, str_off_ptr)[0]
            if str_data_off >= len(data):
                continue
            # ULEB128 length prefix
            pos = str_data_off
            val = 0
            shift = 0
            while pos < len(data):
                b = data[pos]
                val |= (b & 0x7F) << shift
                pos += 1
                if not (b & 0x80):
                    break
                shift += 7
            str_len = val
            if pos + str_len <= len(data) and str_len > 0:
                s = data[pos:pos + str_len].decode("utf-8", errors="replace")
                if len(s) >= 3:
                    strings.append(s)
        except Exception:
            continue

    result.strings_sample = strings[:500]

    # Extract class names from strings (Lcom/example/...)
    result.classes = [s for s in strings if s.startswith("L") and "/" in s and s.endswith(";")][:200]

    return result


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
        ("REJECT", "Frida detection reject"),
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


def _detect_protections(strings: list[str], result: APKAnalysis) -> None:
    """Detect security protections from DEX strings."""
    all_strings_lower = " ".join(strings).lower()

    for category, indicators in _PROTECTION_INDICATORS.items():
        for keyword, description in indicators:
            if keyword.lower() in all_strings_lower:
                result.protections.append({
                    "category": category,
                    "indicator": keyword,
                    "description": description,
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
