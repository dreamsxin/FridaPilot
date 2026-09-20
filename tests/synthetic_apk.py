"""Synthetic APK / AXML / DEX fixtures.

Assembled field by field from the documented on-disk layouts (AOSP
``ResourceTypes.h`` for binary XML, the Dalvik ``dex-format`` header for DEX), so
the expected values are the ones written into the fixture rather than whatever a
parser happens to return.

Caveat: fixture and parser share an author, so a shared misreading of either
format would not be caught. ``FRIDAPILOT_TEST_APK=<path>`` enables the real-APK
test in test_apk_analysis.py, which closes that gap.
"""

from __future__ import annotations

import struct
import zipfile

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

PACKAGE = "com.example.app"
VERSION_NAME = "2.1.0"
VERSION_CODE = 42
MIN_SDK = 24
TARGET_SDK = 34
PERMISSIONS = ["android.permission.INTERNET", "android.permission.CAMERA"]
ACTIVITIES = [PACKAGE + ".MainActivity"]
SERVICES = [PACKAGE + ".MyService"]
RECEIVERS = ["com.other.vendor.BootReceiver"]

POOL_STRINGS = [
    "manifest", "package", "versionCode", "versionName",
    "uses-sdk", "minSdkVersion", "targetSdkVersion",
    "uses-permission", "name", "activity", "service", "receiver",
    PACKAGE, VERSION_NAME, ".MainActivity", "MyService",
    "com.other.vendor.BootReceiver",
    PERMISSIONS[0], PERMISSIONS[1],
]
IDX = {s: i for i, s in enumerate(POOL_STRINGS)}

DEX_STRINGS = ["\u6d4b\u8bd5\u5b57\u7b26abc", "Lcom/example/Foo;", "isDeviceRooted"]
DEX_INDICATOR = "com.topjohnwu.magisk"


def string_pool(strings: list[str]) -> bytes:
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
    return (struct.pack("<HHI", CHUNK_STRING_POOL, 28, 8 + len(payload) + pad)
            + payload + b"\x00" * pad)


def start_element(name_idx: int, attrs: list[tuple[int, int | None, int, int]]) -> bytes:
    ext = struct.pack("<II", 0xFFFFFFFF, name_idx)
    ext += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
    body = b""
    for name_idx_attr, raw_idx, dtype, data in attrs:
        body += struct.pack("<III", 0xFFFFFFFF, name_idx_attr,
                            0xFFFFFFFF if raw_idx is None else raw_idx)
        body += struct.pack("<HBBI", 8, 0, dtype, data)
    payload = struct.pack("<II", 1, 0xFFFFFFFF) + ext + body
    return struct.pack("<HHI", CHUNK_START_ELEMENT, 16, 8 + len(payload)) + payload


def manifest_axml() -> bytes:
    """A binary AndroidManifest.xml with the values named by the constants above."""
    chunks = string_pool(POOL_STRINGS)
    chunks += start_element(IDX["manifest"], [
        (IDX["package"], IDX[PACKAGE], TYPE_STRING, 0),
        (IDX["versionCode"], None, TYPE_INT_DEC, VERSION_CODE),
        (IDX["versionName"], IDX[VERSION_NAME], TYPE_STRING, 0),
    ])
    chunks += start_element(IDX["uses-sdk"], [
        (IDX["minSdkVersion"], None, TYPE_INT_DEC, MIN_SDK),
        (IDX["targetSdkVersion"], None, TYPE_INT_DEC, TARGET_SDK),
    ])
    for perm in PERMISSIONS:
        chunks += start_element(IDX["uses-permission"],
                                [(IDX["name"], IDX[perm], TYPE_STRING, 0)])
    chunks += start_element(IDX["activity"],
                            [(IDX["name"], IDX[".MainActivity"], TYPE_STRING, 0)])
    chunks += start_element(IDX["service"],
                            [(IDX["name"], IDX["MyService"], TYPE_STRING, 0)])
    chunks += start_element(IDX["receiver"],
                            [(IDX["name"], IDX[RECEIVERS[0]], TYPE_STRING, 0)])
    return struct.pack("<HHI", CHUNK_XML, 8, 8 + len(chunks)) + chunks


def dex_bytes(strings: list[str] | None = None, methods: int = 11,
              classes: int = 5) -> bytes:
    """A DEX image. Header fields used: magic[8], checksum@8, file_size@32,
    string_ids_size@56, string_ids_off@60, type_ids_size@64, method_ids_size@88,
    class_defs_size@96. String data is uleb128(UTF-16 length) + MUTF-8 + NUL."""
    strings = DEX_STRINGS if strings is None else strings
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


def write_apk(directory, *, second_dex_indicator: bool = True) -> str:
    """Write a two-dex APK; the protection indicator lives only in classes2.dex."""
    path = directory / "app.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_axml())
        zf.writestr("classes.dex", dex_bytes(strings=["Lcom/example/Foo;", "harmless"]))
        second = [DEX_INDICATOR] if second_dex_indicator else ["also.harmless"]
        zf.writestr("classes2.dex", dex_bytes(strings=second))
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 32)
        zf.writestr("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")
        zf.writestr("META-INF/CERT.RSA", b"\x30\x82" + b"\x00" * 16)
        zf.writestr("res/layout/main.xml", b"\x00" * 8)
    return str(path)
