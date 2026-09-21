"""Tests for fridapilot.tools.apk_analysis.

Accuracy strategy:

* The AXML and DEX fixtures (tests/synthetic_apk.py) are assembled field by field
  from the documented on-disk layouts, and the expected values are the ones
  written into the fixture — not whatever the parser happens to return.
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

from .synthetic_apk import (
    ACTIVITIES,
    CHUNK_XML,
    DEX_INDICATOR,
    DEX_STRINGS,
    MIN_SDK,
    PACKAGE,
    PERMISSIONS,
    RECEIVERS,
    SERVICES,
    TARGET_SDK,
    VERSION_CODE,
    VERSION_NAME,
    dex_bytes,
    manifest_axml,
    string_pool,
    write_apk,
)

# ── manifest parsing ────────────────────────────────────────────────────────

def test_manifest_fields_come_from_attributes_not_string_guessing():
    result = APKAnalysis(filepath="fixture.apk")
    _parse_binary_manifest(manifest_axml(), result)

    assert result.package_name == PACKAGE
    assert result.version_name == VERSION_NAME
    assert result.version_code == VERSION_CODE
    assert result.min_sdk == MIN_SDK
    assert result.target_sdk == TARGET_SDK
    assert result.permissions == PERMISSIONS


def test_component_names_are_qualified_against_the_package():
    result = APKAnalysis(filepath="fixture.apk")
    _parse_binary_manifest(manifest_axml(), result)

    assert result.activities == ACTIVITIES      # ".X" -> pkg + ".X"
    assert result.services == SERVICES          # bare name -> pkg.X
    assert result.receivers == RECEIVERS         # already absolute
    assert result.providers == []


def test_unparsable_manifest_falls_back_to_exact_permission_prefix():
    """A pool with no element chunks: only permissions are recoverable."""
    result = APKAnalysis(filepath="fixture.apk")
    blob = struct.pack("<HHI", CHUNK_XML, 8, 0) + string_pool(
        [PACKAGE, "android.permission.VIBRATE", "not.a.permission"])
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
    path.write_bytes(dex_bytes())
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
    _info, strings = _parse_dex_header(dex_bytes())
    assert strings[0] == "\u6d4b\u8bd5\u5b57\u7b26abc"
    assert strings == DEX_STRINGS


def test_analyze_dex_returns_the_analysis_object(tmp_path):
    path = tmp_path / "classes.dex"
    path.write_bytes(dex_bytes())
    assert analyze_dex(path).version == "035"


def test_non_dex_input_is_reported_as_empty(tmp_path):
    path = tmp_path / "not.dex"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    info = analyze_dex(path)
    assert info.magic == "" and info.class_count == 0


# ── whole-APK analysis ──────────────────────────────────────────────────────

def test_analyze_apk_structure(tmp_path):
    info = analyze_apk(write_apk(tmp_path))

    assert info.package_name == PACKAGE
    assert info.version_code == VERSION_CODE
    assert info.dex_count == 2
    assert info.native_libs == ["lib/arm64-v8a/libnative.so"]
    assert info.has_native_code is True
    assert info.signing_info["signed"] is True
    assert info.signing_info["v1"] is True


def test_protection_scan_covers_every_dex_not_just_the_first(tmp_path):
    hit_dir = tmp_path / "with_hit"
    hit_dir.mkdir()
    with_hit = analyze_apk(write_apk(hit_dir, second_dex_indicator=True))
    # the indicator lives only in classes2.dex
    assert DEX_INDICATOR in {p["indicator"] for p in with_hit.protections}

    clean_dir = tmp_path / "clean"
    clean_dir.mkdir()
    without = analyze_apk(write_apk(clean_dir, second_dex_indicator=False))
    assert without.protections == []


def test_detect_protections_matches_analyze_apk(tmp_path):
    path = write_apk(tmp_path)
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
