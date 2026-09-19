"""Tests for fridapilot.tools.apk_analysis.

Accuracy strategy:

* The AXML and DEX fixtures are assembled field by field from the documented
  on-disk layouts (AOSP ``ResourceTypes.h`` for binary XML, the Dalvik
  ``dex-format`` header for DEX), and the expected values are the ones written
  into the fixture — not whatever the parser happens to return.
* Fixture and parser were written by the same hand, so a shared misreading of the
  format would not be caught here. ``test_real_apk`` closes that gap when a real
  APK is available: set ``FRIDAPILOT_TEST_APK=/path/to/app.apk`` to run it.
* Indicator tests pin the *false positive* cases explicitly ("su" must not match
  "issue"), because that is the behaviour that regressed before.
"""

from __future__ import annotations

import os
import re
import struct
import zipfile

import pytest

from fridapilot.tools.apk_analysis import (
    APKAnalysis,
    _detect_protections,
    _parse_binary_manifest,
    _parse_dex_header,
    analyze_apk,
    analyze_dex,
    detect_protections,
)

# ── binary XML (AXML) fixture ────────────────────────────────────────────────
# ResChunk_header: type u16, headerSize u16, size u32
# ResStringPool_header adds: stringCount u32, styleCount u32, flags u32,
#                            stringsStart u32, stylesStart u32   (headerSize 28)
# ResXMLTree_node:   header(8) + lineNumber u32 + comment u32     (headerSize 16)
# ResXMLTree_attrExt: ns u32, name u32, attributeStart u16, attributeSize u16,
#                     attributeCount u16, idIndex u16, classIndex u16, styleIndex u16
# ResXMLTree_attribute: ns u32, name u32, rawValue u32, Res_value{size u16,
#                     res0 u8, dataType u8, data u32}
CHUNK_XML = 0x0003
CHUNK_STRING_POOL = 0x0001
CHUNK_START_ELEMENT = 0x0102
UTF8_FLAG = 1 << 8
TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10


def _string_pool(strings: list[str]) -> bytes:
    blobs, offsets, cursor = b"", [], 0
    for s in strings:
        encoded = s.encode("utf-8")
        # UTF-8 pool entries carry the UTF-16 length, then the byte length, then
        # the bytes and a NUL terminator.
        item = bytes([len(s), len(encoded)]) + encoded + b"\x00"
        offsets.append(cursor)
        cursor += len(item)
        blobs += item
    strings_start = 28 + 4 * len(strings)
    body = struct.pack("<IIIII", len(strings), 0, UTF8_FLAG, strings_start, 0)
    payload = body + b"".join(struct.pack("<I", o) for o in offsets) + blobs
    pad = (-(8 + len(payload))) % 4
    return struct.pack("<HHI", CHUNK_STRING_POOL, 28, 8 + len(payload) + pad) + payload + b"\x00" * pad


def _start_element(name_idx: int, attrs: list[tuple[int, int | None, int, int]]) -> bytes:
    ext = struct.pack("<II", 0xFFFFFFFF, name_idx)
    ext += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
    body = b""
    for name_idx_attr, raw_idx, dtype, data in attrs:
        body += struct.pack("<III", 0xFFFFFFFF, name_idx_attr,
                            0xFFFFFFFF if raw_idx is None else raw_idx)
        body += struct.pack("<HBBI", 8, 0, dtype, data)
    payload = struct.pack("<II", 1, 0xFFFFFFFF) + ext + body
    return struct.pack("<HHI", CHUNK_START_ELEMENT, 16, 8 + len(payload)) + payload


POOL_STRINGS = [
    "manifest", "package", "versionCode", "versionName",
    "uses-sdk", "minSdkVersion", "targetSdkVersion",
    "uses-permission", "name", "activity", "service", "receiver",
    "com.example.app", "2.1.0", ".MainActivity", "MyService",
    "com.other.vendor.BootReceiver", "android.permission.INTERNET",
    "android.permission.CAMERA",
]
IDX = {s: i for i, s in enumerate(POOL_STRINGS)}


def _manifest_axml() -> bytes:
    chunks = _string_pool(POOL_STRINGS)
    chunks += _start_element(IDX["manifest"], [
        (IDX["package"], IDX["com.example.app"], TYPE_STRING, 0),
        (IDX["versionCode"], None, TYPE_INT_DEC, 42),
        (IDX["versionName"], IDX["2.1.0"], TYPE_STRING, 0),
    ])
    chunks += _start_element(IDX["uses-sdk"], [
        (IDX["minSdkVersion"], None, TYPE_INT_DEC, 24),
        (IDX["targetSdkVersion"], None, TYPE_INT_DEC, 34),
    ])
    for perm in ("android.permission.INTERNET", "android.permission.CAMERA"):
        chunks += _start_element(IDX["uses-permission"],
                                 [(IDX["name"], IDX[perm], TYPE_STRING, 0)])
    chunks += _start_element(IDX["activity"],
                             [(IDX["name"], IDX[".MainActivity"], TYPE_STRING, 0)])
    chunks += _start_element(IDX["service"],
                             [(IDX["name"], IDX["MyService"], TYPE_STRING, 0)])
    chunks += _start_element(IDX["receiver"],
                             [(IDX["name"], IDX["com.other.vendor.BootReceiver"],
                               TYPE_STRING, 0)])
    return struct.pack("<HHI", CHUNK_XML, 8, 8 + len(chunks)) + chunks


# ── DEX fixture ─────────────────────────────────────────────────────────────
# dex header fields used here: magic[8], checksum@8, file_size@32,
# string_ids_size@56, string_ids_off@60, type_ids_size@64, method_ids_size@88,
# class_defs_size@96. String data is uleb128(UTF-16 length) + MUTF-8 + NUL.
DEX_STRINGS = ["\u6d4b\u8bd5\u5b57\u7b26abc", "Lcom/example/Foo;", "isDeviceRooted"]


def _dex(strings: list[str] = DEX_STRINGS, methods: int = 11, classes: int = 5) -> bytes:
    data, offsets = b"", []
    for s in strings:
        encoded = s.encode("utf-8")
        offsets.append(len(data))
        data += bytes([len(s)]) + encoded + b"\x00"

    header = bytearray(112)
    header[0:8] = b"dex\n035\x00"
    ids_off = 112
    struct.pack_into("<I", header, 8, 0x12345678)       # checksum
    struct.pack_into("<I", header, 32, 112 + 4 * len(strings) + len(data))
    struct.pack_into("<I", header, 56, len(strings))    # string_ids_size
    struct.pack_into("<I", header, 60, ids_off)         # string_ids_off
    struct.pack_into("<I", header, 64, 7)               # type_ids_size
    struct.pack_into("<I", header, 88, methods)         # method_ids_size
    struct.pack_into("<I", header, 96, classes)         # class_defs_size
    ids = b"".join(struct.pack("<I", ids_off + 4 * len(strings) + o) for o in offsets)
    return bytes(header) + ids + data


# ── manifest parsing ────────────────────────────────────────────────────────

def test_manifest_fields_come_from_attributes_not_string_guessing():
    result = APKAnalysis(filepath="fixture.apk")
    _parse_binary_manifest(_manifest_axml(), result)

    assert result.package_name == "com.example.app"
    assert result.version_name == "2.1.0"
    assert result.version_code == 42
    assert result.min_sdk == 24
    assert result.target_sdk == 34
    assert result.permissions == ["android.permission.INTERNET",
                                  "android.permission.CAMERA"]


def test_component_names_are_qualified_against_the_package():
    result = APKAnalysis(filepath="fixture.apk")
    _parse_binary_manifest(_manifest_axml(), result)

    assert result.activities == ["com.example.app.MainActivity"]   # ".X" -> pkg + ".X"
    assert result.services == ["com.example.app.MyService"]        # bare name -> pkg.X
    assert result.receivers == ["com.other.vendor.BootReceiver"]   # already absolute
    assert result.providers == []


def test_unparsable_manifest_falls_back_to_exact_permission_prefix():
    """A pool with no element chunks: only permissions are recoverable."""
    result = APKAnalysis(filepath="fixture.apk")
    blob = struct.pack("<HHI", CHUNK_XML, 8, 0) + _string_pool(
        ["com.example.app", "android.permission.VIBRATE", "not.a.permission"])
    _parse_binary_manifest(blob, result)

    assert result.permissions == ["android.permission.VIBRATE"]
    assert result.package_name == ""       # never guessed from arbitrary strings
    assert result.activities == []


# ── protection indicators ───────────────────────────────────────────────────

@pytest.mark.parametrize("benign", [
    "issue",                 # contains "su"
    "consumer",              # contains "su"
    "Lcom/example/Result;",  # contains "su"
    "generic_thing",         # contains "generic"
    "resume",                # contains "su"
    "subscription",          # starts with "su"
])
def test_short_indicators_do_not_match_inside_words(benign):
    result = APKAnalysis(filepath="x.apk")
    _detect_protections([benign], result)
    assert result.protections == [], (benign, result.protections)


@pytest.mark.parametrize("value,indicator", [
    ("/system/xbin/su", "su"),
    ("which su", "su"),
    ("com.topjohnwu.magisk", "com.topjohnwu.magisk"),
    ("okhttp3.CertificatePinner", "CertificatePinner"),
    ("Build.FINGERPRINT", "Build.FINGERPRINT"),
    ("ro.kernel.qemu goldfish", "goldfish"),
    ("frida-server", "frida"),
    ("tcp:27042", "27042"),
])
def test_real_indicators_still_match_and_carry_evidence(value, indicator):
    result = APKAnalysis(filepath="x.apk")
    _detect_protections([value], result)
    hits = {p["indicator"]: p for p in result.protections}
    assert indicator in hits, (value, sorted(hits))
    assert hits[indicator]["match"] == value
    assert hits[indicator]["category"]
    assert hits[indicator]["description"]


def test_indicator_scan_is_per_string_not_on_a_joined_blob():
    """"isDeviceRooted" split across two strings must not be reassembled."""
    result = APKAnalysis(filepath="x.apk")
    _detect_protections(["isDevice", "Rooted"], result)
    assert "isDeviceRooted" not in {p["indicator"] for p in result.protections}


# ── DEX parsing ─────────────────────────────────────────────────────────────

def test_dex_header_counts(tmp_path):
    path = tmp_path / "classes.dex"
    path.write_bytes(_dex())
    info = analyze_dex(path)

    assert info.magic == "dex\n"      # the DEX magic is literally "dex\n035\0"

    assert info.version == "035"
    assert info.checksum == 0x12345678
    assert info.class_count == 5
    assert info.method_count == 11
    assert info.string_count == len(DEX_STRINGS)
    assert info.classes == ["Lcom/example/Foo;"]


def test_dex_strings_are_not_truncated_at_the_utf16_length():
    """The uleb128 prefix counts UTF-16 units; reading it as bytes truncates."""
    _info, strings = _parse_dex_header(_dex())
    assert strings[0] == "\u6d4b\u8bd5\u5b57\u7b26abc"
    assert strings == DEX_STRINGS


def test_analyze_dex_returns_the_analysis_object(tmp_path):
    path = tmp_path / "classes.dex"
    path.write_bytes(_dex())
    assert analyze_dex(path).version == "035"


def test_non_dex_input_is_reported_as_empty(tmp_path):
    path = tmp_path / "not.dex"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    info = analyze_dex(path)
    assert info.magic == "" and info.class_count == 0


# ── whole-APK analysis ──────────────────────────────────────────────────────

def _apk(tmp_path, *, second_dex_indicator: bool = True):
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", _manifest_axml())
        zf.writestr("classes.dex", _dex(strings=["Lcom/example/Foo;", "harmless"]))
        second = ["com.topjohnwu.magisk"] if second_dex_indicator else ["also.harmless"]
        zf.writestr("classes2.dex", _dex(strings=second))
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 32)
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        zf.writestr("META-INF/CERT.RSA", b"\x30\x82" + b"\x00" * 16)
        zf.writestr("res/layout/main.xml", b"\x00" * 8)
    return path


def test_analyze_apk_structure(tmp_path):
    info = analyze_apk(_apk(tmp_path))

    assert info.package_name == "com.example.app"
    assert info.version_code == 42
    assert info.dex_count == 2
    assert info.native_libs == ["lib/arm64-v8a/libnative.so"]
    assert info.has_native_code is True
    assert info.signing_info["signed"] is True
    assert info.signing_info["v1"] is True


def test_protection_scan_covers_every_dex_not_just_the_first(tmp_path):
    hit_dir = tmp_path / "with_hit"
    hit_dir.mkdir()
    with_hit = analyze_apk(_apk(hit_dir, second_dex_indicator=True))
    # the indicator lives only in classes2.dex
    assert "com.topjohnwu.magisk" in {p["indicator"] for p in with_hit.protections}

    clean_dir = tmp_path / "clean"
    clean_dir.mkdir()
    without = analyze_apk(_apk(clean_dir, second_dex_indicator=False))
    assert without.protections == []



def test_detect_protections_matches_analyze_apk(tmp_path):
    path = _apk(tmp_path)
    assert detect_protections(path) == analyze_apk(path).protections


def test_non_zip_input_returns_empty_analysis(tmp_path):
    path = tmp_path / "broken.apk"
    path.write_bytes(b"not a zip")
    info = analyze_apk(path)
    assert info.package_name == "" and info.dex_count == 0


# ── optional oracle: a real APK, if the caller provides one ─────────────────

@pytest.mark.skipif(not os.environ.get("FRIDAPILOT_TEST_APK"),
                    reason="set FRIDAPILOT_TEST_APK to validate against a real APK")
def test_real_apk():
    path = os.environ["FRIDAPILOT_TEST_APK"]
    info = analyze_apk(path)

    assert re.fullmatch(r"[A-Za-z][\w]*(\.[A-Za-z_][\w]*)+", info.package_name), \
        info.package_name
    assert info.dex_count >= 1
    assert info.permissions == [] or all(p.count(".") >= 2 for p in info.permissions)
    for component in info.activities + info.services + info.receivers + info.providers:
        assert "." in component and not component.startswith("."), component
    for hit in info.protections:
        assert hit["indicator"].lower() in hit["match"].lower(), hit
