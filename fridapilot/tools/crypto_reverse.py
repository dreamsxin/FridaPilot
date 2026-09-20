"""Crypto Reverse Tools - Binary encryption analysis and key extraction.

Static analysis + dynamic Frida hooking for reverse engineering
cryptographic implementations in PE/ELF binaries.

Inspired by the 6-level protection model:
  L0: Plaintext key/IV in .rdata (static analysis)
  L1: XOR obfuscated keys (deobfuscation)
  L2: Key derivation (PBKDF2/HKDF/scrypt - hook derivation material)
  L3: White-box AES (DFA attack / T-table extraction)
  L4: Server-delivered keys (Frida hook BCrypt API / packet capture)
  L5: TPM/DPAPI hardware-bound (hook CryptUnprotectData)

No LLM dependency.
"""

from __future__ import annotations

import struct
import math
from dataclasses import dataclass, field
from pathlib import Path


# AES S-Box (standard, used for fingerprinting)
AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
])

# Crypto API signatures for detection
CRYPTO_IMPORTS_BCRYPT = [
    "BCryptOpenAlgorithmProvider", "BCryptGenerateSymmetricKey",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptDeriveKeyPBKDF2",
    "BCryptSetProperty", "BCryptDestroyKey", "BCryptCloseAlgorithmProvider",
]
CRYPTO_IMPORTS_LEGACY = [
    "CryptAcquireContext", "CryptCreateHash", "CryptDeriveKey",
    "CryptEncrypt", "CryptDecrypt", "CryptProtectData", "CryptUnprotectData",
]
CRYPTO_IMPORTS_OPENSSL = [
    "EVP_EncryptInit", "EVP_DecryptInit", "EVP_CipherInit",
    "AES_set_encrypt_key", "AES_set_decrypt_key",
]

@dataclass
class ProtectionLevel:
    """Detection result for binary crypto protection level."""
    level: int  # 0-5
    label: str
    confidence: str  # HIGH / MEDIUM / LOW
    evidence: list[str] = field(default_factory=list)


@dataclass
class CryptoScanResult:
    """Result of scanning a binary for crypto indicators."""
    filepath: str
    is_pe: bool = False
    is_64bit: bool = False
    is_dotnet: bool = False
    sbox_offsets: list[int] = field(default_factory=list)
    crypto_strings: list[str] = field(default_factory=list)
    crypto_imports: list[str] = field(default_factory=list)
    hex_key_candidates: list[str] = field(default_factory=list)
    protection_level: ProtectionLevel | None = None


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def find_sbox(data: bytes) -> list[int]:
    """Find all occurrences of the standard AES S-Box in binary data."""
    offsets = []
    start = 0
    while True:
        idx = data.find(AES_SBOX, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def extract_crypto_strings(data: bytes) -> list[str]:
    """Extract crypto-related ASCII strings from binary data."""
    keywords = [
        b"aes", b"des", b"rsa", b"rijndael", b"encrypt", b"decrypt",
        b"crypto", b"cipher", b"bcrypt", b"base64", b"hmac", b"pbkdf",
        b"sha", b"md5", b"key", b"secret", b"password", b"token",
        b"chainingmode", b"keydatablob", b"padding",
    ]
    results = []
    # Extract printable ASCII runs (min 4 chars)
    current = []
    for b in data:
        if 0x20 <= b < 0x7f:
            current.append(chr(b))
        else:
            if len(current) >= 4:
                s = "".join(current)
                if any(kw.decode() in s.lower() for kw in keywords):
                    results.append(s)
            current = []
    return list(set(results))


def detect_crypto_imports(data: bytes) -> dict[str, list[str]]:
    """Detect crypto API imports in binary data."""
    found: dict[str, list[str]] = {"bcrypt_cng": [], "cryptoapi": [], "openssl": []}
    for name in CRYPTO_IMPORTS_BCRYPT:
        if name.encode() in data:
            found["bcrypt_cng"].append(name)
    for name in CRYPTO_IMPORTS_LEGACY:
        if name.encode() in data:
            found["cryptoapi"].append(name)
    for name in CRYPTO_IMPORTS_OPENSSL:
        if name.encode() in data:
            found["openssl"].append(name)
    return {k: v for k, v in found.items() if v}

def detect_protection_level(data: bytes) -> ProtectionLevel:
    """Detect the crypto key protection level of a binary (L0-L5)."""
    evidence: list[str] = []

    # L5: TPM / DPAPI hardware binding
    hw_markers = [
        b"NCryptOpenStorageProvider", b"NCryptCreatePersistedKey",
        b"CryptProtectData", b"CryptUnprotectData",
        b"Tbsi_Context_Create", b"TPM",
        b"Microsoft Platform Crypto Provider",
    ]
    hw_hits = [m.decode() for m in hw_markers if m in data]
    if hw_hits:
        return ProtectionLevel(5, "TPM/DPAPI hardware-bound", "HIGH", hw_hits)

    # L4: Server-delivered key
    server_markers = [
        b"fetch_key", b"download_key", b"key_exchange",
        b"BACKEND_SECRET", b"SERVER_KEY", b"REPLACE_WITH",
    ]
    srv_hits = [m.decode() for m in server_markers if m in data]
    if srv_hits:
        return ProtectionLevel(4, "Server-delivered key", "HIGH", srv_hits)

    # L3: White-box AES (large high-entropy regions, no standard S-Box)
    sbox_offsets = find_sbox(data)
    # Scan for large continuous high-entropy blocks (T-tables > 40KB)
    high_entropy_regions = 0
    block_size = 4096
    for i in range(0, len(data) - block_size, block_size):
        if shannon_entropy(data[i:i + block_size]) > 7.5:
            high_entropy_regions += 1
    if high_entropy_regions > 10 and not sbox_offsets:
        evidence.append(f"{high_entropy_regions} high-entropy 4KB blocks, no standard S-Box")
        return ProtectionLevel(3, "White-box AES (T-tables)", "MEDIUM", evidence)

    # L2: Key derivation
    kdf_markers = [
        b"BCryptDeriveKeyPBKDF2", b"PBKDF2", b"HKDF", b"scrypt", b"argon2",
        b"EVP_BytesToKey", b"machine_id", b"device_id", b"install_time",
        b"GetVolumeInformation", b"GetComputerName",
    ]
    kdf_hits = [m.decode() for m in kdf_markers if m in data]
    if kdf_hits:
        return ProtectionLevel(2, "Key derivation (KDF)", "HIGH", kdf_hits)

    # L1: XOR obfuscation patterns
    xor_patterns = [b"\x34", b"\x30\xc1", b"\x80\xf1"]  # XOR AL,imm / XOR CL,imm
    xor_count = sum(data.count(p) for p in xor_patterns)
    if xor_count > 50:
        evidence.append(f"XOR instruction patterns: {xor_count} occurrences")
        return ProtectionLevel(1, "XOR obfuscation", "MEDIUM", evidence)

    # L0: Plaintext key adjacent to S-Box
    if sbox_offsets:
        for offset in sbox_offsets:
            # Check 32/48/64 bytes before S-Box for high-entropy blocks
            for key_len in [16, 24, 32]:
                if offset >= key_len:
                    candidate = data[offset - key_len : offset]
                    ent = shannon_entropy(candidate)
                    if ent > 3.5 and candidate != b"\x00" * key_len:
                        evidence.append(
                            f"S-Box@0x{offset:x}, {key_len}B candidate before it, entropy={ent:.2f}"
                        )
        if evidence:
            return ProtectionLevel(0, "Plaintext key in .rdata", "HIGH", evidence)
        return ProtectionLevel(0, "S-Box found, key location unknown", "LOW",
                               [f"S-Box at offset 0x{o:x}" for o in sbox_offsets])

    return ProtectionLevel(-1, "No crypto indicators found", "LOW", [])


def scan_binary(filepath: str | Path) -> CryptoScanResult:
    """Full crypto scan of a binary file."""
    filepath = Path(filepath)
    data = filepath.read_bytes()

    result = CryptoScanResult(filepath=str(filepath))

    # PE detection
    if data[:2] == b"MZ":
        result.is_pe = True
        # Check PE signature
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0] if len(data) > 0x40 else 0
        if pe_offset and pe_offset + 6 < len(data) and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
            result.is_64bit = machine == 0x8664
        # .NET detection
        result.is_dotnet = b"BSJB" in data

    result.sbox_offsets = find_sbox(data)
    result.crypto_strings = extract_crypto_strings(data)
    imports = detect_crypto_imports(data)
    result.crypto_imports = [api for apis in imports.values() for api in apis]

    # Find hex-encoded key candidates (32-64 hex chars = 16-32 bytes)
    import re
    hex_pattern = re.compile(rb"[0-9a-fA-F]{32,64}")
    for m in hex_pattern.finditer(data):
        candidate = m.group().decode()
        if len(candidate) in (32, 48, 64):
            result.hex_key_candidates.append(candidate)

    result.protection_level = detect_protection_level(data)
    return result


def get_bcrypt_hook_script() -> str:
    """Get a Frida script that hooks Windows BCrypt APIs to capture keys."""
    return """\
// Hook BCrypt APIs to capture encryption keys and parameters
const bcrypt = Module.findModuleByName('bcrypt.dll');
if (bcrypt) {
    // BCryptGenerateSymmetricKey - captures key material
    const genKey = Module.findExportByName('bcrypt.dll', 'BCryptGenerateSymmetricKey');
    if (genKey) {
        Interceptor.attach(genKey, {
            onEnter(args) {
                this.hAlgorithm = args[0];
                this.phKey = args[1];
                this.pbKeyObject = args[2];
                this.cbKeyObject = args[3].toInt32();
                this.pbSecret = args[4];
                this.cbSecret = args[5].toInt32();
            },
            onLeave(retval) {
                if (retval.toInt32() === 0 && this.cbSecret > 0) {
                    const key = Memory.readByteArray(this.pbSecret, this.cbSecret);
                    send({ type: 'crypto_key', api: 'BCryptGenerateSymmetricKey',
                           key: Array.from(new Uint8Array(key)).map(b => ('0'+b.toString(16)).slice(-2)).join(''),
                           size: this.cbSecret });
                }
            }
        });
    }

    // BCryptEncrypt - captures plaintext and IV
    const encrypt = Module.findExportByName('bcrypt.dll', 'BCryptEncrypt');
    if (encrypt) {
        Interceptor.attach(encrypt, {
            onEnter(args) {
                this.pbInput = args[1];
                this.cbInput = args[2].toInt32();
                this.pbIV = args[4];
                this.cbIV = args[5].toInt32();
            },
            onLeave(retval) {
                if (retval.toInt32() === 0) {
                    const msg = { type: 'bcrypt_encrypt', inputSize: this.cbInput };
                    if (this.cbIV > 0 && !this.pbIV.isNull()) {
                        const iv = Memory.readByteArray(this.pbIV, this.cbIV);
                        msg.iv = Array.from(new Uint8Array(iv)).map(b => ('0'+b.toString(16)).slice(-2)).join('');
                    }
                    send(msg);
                }
            }
        });
    }

    // BCryptDecrypt - captures ciphertext and IV
    const decrypt = Module.findExportByName('bcrypt.dll', 'BCryptDecrypt');
    if (decrypt) {
        Interceptor.attach(decrypt, {
            onEnter(args) {
                this.pbInput = args[1];
                this.cbInput = args[2].toInt32();
                this.pbIV = args[4];
                this.cbIV = args[5].toInt32();
            },
            onLeave(retval) {
                if (retval.toInt32() === 0) {
                    const msg = { type: 'bcrypt_decrypt', inputSize: this.cbInput };
                    if (this.cbIV > 0 && !this.pbIV.isNull()) {
                        const iv = Memory.readByteArray(this.pbIV, this.cbIV);
                        msg.iv = Array.from(new Uint8Array(iv)).map(b => ('0'+b.toString(16)).slice(-2)).join('');
                    }
                    send(msg);
                }
            }
        });
    }

    console.log('[FridaPilot] BCrypt API hooks applied');
} else {
    console.log('[FridaPilot] bcrypt.dll not found');
}
"""


@dataclass
class BruteforceResult:
    """Result of a brute-force key search."""
    found: bool = False
    key_hex: str = ""
    iv_hex: str = ""
    key_offset: int = 0
    key_size: int = 0
    iv_strategy: str = ""
    printable_ratio: float = 0.0
    plaintext_preview: str = ""


def bruteforce_key(
    binary_path: str | Path,
    ciphertext: bytes,
    key_sizes: list[int] | None = None,
    alignment: int = 16,
    iv_strategies: list[str] | None = None,
    printable_threshold: float = 0.75,
    max_candidates: int = 5,
) -> list[BruteforceResult]:
    """Brute-force search for AES key in a binary file.

    Iterates aligned blocks in the binary as candidate AES keys,
    tries decryption, and checks if the result looks like plaintext.

    Args:
        binary_path: Path to the binary file containing the key.
        ciphertext: The encrypted data to attempt decryption on.
        key_sizes: Key sizes to try (default: [16, 32]).
        alignment: Byte alignment for candidate offsets (16=fast, 4=thorough, 1=exhaustive).
        iv_strategies: IV strategies: "first16" (prepended IV), "zero", "adjacent".
        printable_threshold: Minimum ratio of printable chars to consider valid.
        max_candidates: Maximum number of results to return.

    Returns:
        List of BruteforceResult for each successful decryption candidate.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding

    if key_sizes is None:
        key_sizes = [16, 32]
    if iv_strategies is None:
        iv_strategies = ["first16", "zero", "adjacent"]

    binary_data = Path(binary_path).read_bytes()
    results: list[BruteforceResult] = []

    def try_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes | None:
        try:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            dec = cipher.decryptor()
            plaintext = dec.update(ct) + dec.finalize()
            # Try PKCS7 unpadding
            try:
                unpadder = padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(plaintext) + unpadder.finalize()
            except Exception:
                pass
            return plaintext
        except Exception:
            return None

    def printable_ratio(data: bytes) -> float:
        if not data:
            return 0.0
        count = sum(1 for b in data if 0x20 <= b < 0x7f or b in (0x0a, 0x0d, 0x09))
        return count / len(data)

    for ks in key_sizes:
        for offset in range(0, len(binary_data) - ks, alignment):
            candidate_key = binary_data[offset : offset + ks]
            # Skip trivial blocks
            if candidate_key == b"\x00" * ks or candidate_key == b"\xff" * ks:
                continue

            for iv_strat in iv_strategies:
                if iv_strat == "first16":
                    iv = ciphertext[:16]
                    ct = ciphertext[16:]
                elif iv_strat == "zero":
                    iv = b"\x00" * 16
                    ct = ciphertext
                elif iv_strat == "adjacent":
                    iv_offset = offset + ks
                    if iv_offset + 16 > len(binary_data):
                        continue
                    iv = binary_data[iv_offset : iv_offset + 16]
                    ct = ciphertext
                else:
                    continue

                if len(ct) == 0 or len(ct) % 16 != 0:
                    continue

                plaintext = try_decrypt(candidate_key, iv, ct)
                if plaintext is None:
                    continue

                ratio = printable_ratio(plaintext)
                if ratio >= printable_threshold:
                    results.append(BruteforceResult(
                        found=True,
                        key_hex=candidate_key.hex(),
                        iv_hex=iv.hex(),
                        key_offset=offset,
                        key_size=ks,
                        iv_strategy=iv_strat,
                        printable_ratio=ratio,
                        plaintext_preview=plaintext[:200].decode("utf-8", errors="replace"),
                    ))
                    if len(results) >= max_candidates:
                        return results

    return results


def xor_deobfuscate(data: bytes, key: bytes) -> bytes:
    """XOR deobfuscate data with a repeating key."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def find_xor_key(
    encrypted: bytes,
    known_plaintext: bytes,
) -> bytes:
    """Recover XOR key from known plaintext + ciphertext pair.

    If you know part of the plaintext (e.g., file header magic bytes),
    XOR it with the ciphertext to recover the key.
    """
    key_len = min(len(encrypted), len(known_plaintext))
    return bytes(encrypted[i] ^ known_plaintext[i] for i in range(key_len))


def bruteforce_single_byte_xor(data: bytes, top_n: int = 3) -> list[tuple[int, float, str]]:
    """Try all 256 single-byte XOR keys, rank by printable ratio.

    Returns:
        List of (key_byte, printable_ratio, preview) sorted by ratio descending.
    """
    results = []
    for key_byte in range(256):
        decrypted = bytes(b ^ key_byte for b in data)
        printable = sum(1 for b in decrypted if 0x20 <= b < 0x7f or b in (0x0a, 0x0d, 0x09))
        ratio = printable / len(data) if data else 0.0
        preview = decrypted[:80].decode("utf-8", errors="replace")
        results.append((key_byte, ratio, preview))
    results.sort(key=lambda x: x[1], reverse=True)
    return results[:top_n]
