"""Prompt Templates - Task-specific LLM prompts for reverse engineering analysis.

Inspired by r2ai's named prompt template system and real-world RE experience
from the antidetect browser project (Electron + Go IPC + custom Chromium kernel).

Each template encodes hard-won lessons:
- Static analysis before dynamic hooking
- Multi-layer target decomposition (Electron/Go/native)
- IPC boundary identification
- Crypto layering (transport + IPC + config)
- Exit code hunting for validation functions
- Go pclntab exploitation for free metadata

Usage:
    from fridapilot.agent.prompts import get_prompt
    prompt = get_prompt("analyze_vulns", context={"disassembly": "...", "imports": [...]})
"""

from __future__ import annotations

from typing import Any


# ── Template Registry ─────────────────────────────────────────

TEMPLATES: dict[str, str] = {}


def get_prompt(template_name: str, **context: Any) -> str:
    """Get a filled prompt template by name.

    Args:
        template_name: One of the registered template names.
        **context: Key-value pairs to fill into the template.

    Returns:
        Formatted prompt string ready for LLM consumption.

    Raises:
        KeyError: If template_name is not registered.
    """
    if template_name not in TEMPLATES:
        available = ", ".join(sorted(TEMPLATES.keys()))
        raise KeyError(f"Unknown prompt template '{template_name}'. Available: {available}")
    return TEMPLATES[template_name].format(**context)


def list_templates() -> list[dict[str, str]]:
    """List all available prompt templates with their descriptions."""
    return [
        {"name": name, "preview": template[:120].replace("\n", " ")}
        for name, template in sorted(TEMPLATES.items())
    ]


# ── analyze_vulns ─────────────────────────────────────────────

TEMPLATES["analyze_vulns"] = """\
You are a security vulnerability analyst. Analyze the following binary/code context \
for potential security vulnerabilities.

Binary Info:
{binary_info}

Disassembly / Decompiled Code:
{code}

Imports:
{imports}

Strings of Interest:
{strings}

Tasks:
1. Identify potential vulnerabilities (buffer overflow, format string, use-after-free, \
integer overflow, command injection, path traversal, insecure crypto, hardcoded credentials).
2. For each vulnerability found, provide:
   - Type and severity (Critical/High/Medium/Low)
   - Location (address/function)
   - Description of the issue
   - Potential exploitation scenario
   - Recommended mitigation
3. Flag any suspicious patterns: anti-analysis, packing, obfuscation, shellcode.
4. Summarize the overall security posture.

Output as structured JSON with a "vulnerabilities" array and "summary" string."""


# ── analyze_crypto ────────────────────────────────────────────

TEMPLATES["analyze_crypto"] = """\
You are a cryptographic analysis expert. Analyze the encryption implementation \
in this binary based on the following evidence.

## Real-World Lessons (from antidetect browser RE)
- Apps often use MULTIPLE encryption layers: transport (TLS) + IPC (AES-CBC with named tags) + \
  config files (AES-128-CBC with derived keys). Analyze each layer independently.
- Key derivation chains are common: MD5(machine_hash + salt) -> AES key -> decrypt config -> \
  get second key -> decrypt IPC. Follow the chain, don't assume a single key.
- Look for CRYPTO_MODE string constants (e.g., "NATIVE_STARTINFO", "NATIVE_IPC", "NETWORK") \
  that indicate different encryption contexts with different keys.
- Go binaries embed crypto function names in pclntab: search for BizEncrypt/BizDecrypt/AESEncrypt.
- BCrypt CNG on Windows: the key is often derived, not stored directly. Hook BCryptGenerateSymmetricKey \
  to capture the actual runtime key, not just the seed material.
- init.json / config files: check if they're AES-encrypted with a key derived from machine_hash \
  or device_id. The key derivation function is the real target, not the AES operation.

Crypto Scan Results:
{crypto_scan}

Protection Level: {protection_level}

Relevant Imports:
{imports}

Crypto-Related Strings:
{strings}

Disassembly Around S-Box / Key Material:
{disassembly}

Tasks:
1. Identify ALL encryption layers (not just one — apps often have 3+).
2. For each layer, determine: algorithm, mode, key source, IV strategy.
3. Trace the key derivation chain from root material to final key.
4. Assess key management:
   - How are keys generated/stored/derived?
   - Are there hardcoded keys, IVs, or salts?
   - Does the key derive from machine-specific data (machine_hash, device_id, install_time)?
5. Identify the optimal interception point:
   - Can we hook at BCrypt/OpenSSL API level? (L4: easiest)
   - Can we extract the derived key? (L2: hook KDF)
   - Is the key static in .rdata? (L0: just read it)
6. Map CRYPTO_MODE constants to their encryption contexts.

Output as structured JSON with "layers" (array of encryption layers), \
"key_derivation_chain", "interception_points", and "attack_strategy" fields."""


# ── auto_name ─────────────────────────────────────────────────

TEMPLATES["auto_name"] = """\
You are a reverse engineering expert specializing in function identification. \
Suggest meaningful names for the following functions based on their behavior.

Binary Context:
{binary_info}

Functions to Name:
{functions}

For each function, analyze:
- The disassembly/decompilation
- Called APIs and library functions
- String references
- Argument patterns and return values
- Calling convention and parameter count

Output a JSON array where each entry has:
- "address": the function address
- "current_name": the current name (if any)
- "suggested_name": your suggested descriptive name (use snake_case)
- "confidence": HIGH/MEDIUM/LOW
- "reasoning": brief explanation of why this name fits

Naming conventions:
- Use verb_noun format (e.g., decrypt_config, validate_license, send_ipc_message)
- Prefix with module context when helpful (e.g., crypto_derive_key, ipc_handle_init)
- For C++ methods, suggest class::method format
- For Go functions, suggest package.FuncName format"""


# ── explain_function ──────────────────────────────────────────

TEMPLATES["explain_function"] = """\
You are a reverse engineering expert. Explain what the following function does \
in clear, technical language.

Function at address: {address}
Module: {module}

Disassembly:
{disassembly}

Known Imports Referenced:
{imports}

String References:
{strings}

Cross-References (callers):
{xrefs}

Provide:
1. **Summary**: One-line description of what this function does.
2. **Detailed Analysis**: Step-by-step explanation of the function's logic.
3. **Parameters**: Describe each parameter's likely type and purpose.
4. **Return Value**: What does it return and when?
5. **Side Effects**: Any global state changes, file I/O, network calls, etc.
6. **Calling Context**: Based on xrefs, when/why is this function called?
7. **Suggested Name**: A descriptive function name.

Output as structured JSON with the fields above."""


# ── analyze_protocol ──────────────────────────────────────────

TEMPLATES["analyze_protocol"] = """\
You are a protocol reverse engineering expert. Analyze the following IPC/network \
protocol based on captured messages and binary analysis.

## Real-World Lessons (from Named Pipe IPC + Electron + Go RE)
- Named Pipe IPC often has a HANDSHAKE phase: Init message (encrypted) -> Status response -> \
  operational messages. Identify the handshake before analyzing data flow.
- Pipe names may be hardcoded with validation (e.g., must start with "appprefix"). \
  Check for string comparisons on pipe names in the binary.
- IPC encryption often uses a DIFFERENT key per message type (e.g., NATIVE_STARTINFO vs NATIVE_IPC). \
  Each crypto mode constant maps to a separate AES key.
- Go IPC servers use protobuf or protojson internally but may wrap in JSON externally. \
  Check for both proto field names (snake_case) and JSON field names (camelCase).
- The IPC client/server roles may be REVERSED from what you expect: \
  the Electron app creates the pipe (server), the Go process connects (client).
- Heartbeat/keepalive messages maintain the connection. If they stop, the subprocess may exit.
- Mock server approach: for API dependencies, build a local HTTPS mock that returns the \
  expected response format. Identify required response fields by crash analysis.
- Child process environment: the IPC subprocess often requires specific command-line args \
  (e.g., -gt <GroupTag> -it <IPCTag> -p <core_path>) passed by the parent.

Captured Messages:
{messages}

Binary Analysis:
{binary_info}

String References:
{strings}

Related Functions:
{functions}

Tasks:
1. Identify the IPC mechanism: Named Pipe / Unix socket / TCP / gRPC / Mojo / custom.
2. Map the message lifecycle:
   a. Connection establishment (pipe name, auth, handshake)
   b. Init/handshake messages (what info is exchanged?)
   c. Operational messages (request types, response format)
   d. Keepalive/heartbeat pattern
   e. Shutdown/disconnect
3. For each message type:
   - Direction (client->server or server->client)
   - Encoding (JSON / protobuf / protojson / binary / encrypted)
   - Encryption layer (if any: which CRYPTO_MODE, which key)
   - Required fields and their types
   - Example payload structure
4. Identify the MINIMUM viable mock: what responses are needed to keep the app running?
5. Document command-line arguments that configure the IPC (pipe names, tags, paths).
6. Note any protobuf .proto definitions that can be inferred from field patterns.

Output as structured JSON with "mechanism", "lifecycle", "message_types" (array), \
"encryption", "mock_requirements", and "cli_args" fields."""


# ── analyze_electron ──────────────────────────────────────────

TEMPLATES["analyze_electron"] = """\
You are an Electron application reverse engineering expert. Analyze the following \
Electron/Chromium-based application.

## Real-World Lessons (from antidetect browser RE)
- app.asar may use OBFUSCATED filenames (hash-based). Don't assume standard structure. \
  Use runtime analysis (require hooks) instead of static asar extraction.
- The main process JS often uses string array rotation obfuscation. \
  Look for decodeRuntimeSecret() or similar deobfuscation functions.
- Custom Chromium kernels (chrome.dll) may have exit code validation: \
  10000 = missing args, 10001 = startup verify fail, 10009 = token verify fail, 10002 = license fail. \
  Search for exit code constants to find validation functions.
- BrowserWindow security flags are your friend: check nodeIntegration, contextIsolation, \
  sandbox, webSecurity for each window.
- Electron Fuses control security at build time. Modifying fuses can enable --inspect, \
  runAsNode, etc. But some fuses are enforced by code checks, not just the fuse byte.
- The app.asar.unpacked/ directory often contains native binaries (Go IPC servers, \
  gateway proxies) that are MORE interesting than the JS code.
- DevTools can be blocked by: devtools-opened event listeners, keyboard shortcut interception, \
  Electron Fuses, or runtime checks. Try Frida-based DevTools opener as fallback.
- contextBridge exposes APIs from main to renderer — enumerate these to understand \
  what the renderer can do.
- IPC channels (ipcMain.handle/on) are the attack surface between renderer and main process.

Application Info:
{app_info}

Modules Found:
{modules}

IPC Channels:
{ipc_channels}

Security Configuration:
{security_config}

Strings of Interest:
{strings}

Tasks:
1. Map the process tree: main process + renderer(s) + child processes (native binaries).
2. For each process, identify its role and communication channels.
3. Analyze security posture:
   - BrowserWindow flags per window
   - Fuse states
   - contextBridge API surface
   - IPC channel permissions
4. Identify the most valuable hook targets:
   - Crypto/auth functions
   - IPC message handlers
   - License/token validation
   - Fingerprint injection points
5. Suggest the optimal RE approach for each layer.
6. If custom Chromium: identify modifications from stock Chromium (validation checks, \
   fingerprint injection, custom startup args).

Output as structured JSON with "process_tree", "security", "ipc_surface", \
"hook_targets", and "re_approach" fields."""


# ── analyze_validation ────────────────────────────────────────

TEMPLATES["analyze_validation"] = """\
You are a software protection analysis expert. Analyze the validation/license/token \
checking mechanism in this binary.

## Real-World Lessons (from antidetect browser protection bypass)
- Validation functions often have a simple boolean return (mov eax,1; ret for pass). \
  The challenge is FINDING them, not bypassing them.
- Exit codes are the key clue: search for non-standard exit codes (10000, 10001, 10009) \
  in the binary. The code calling ExitProcess with that code is near the validation.
- Token validation chains: token -> decrypt -> parse JSON -> check expiry -> check machine_hash. \
  Bypassing just one check may not be enough if there are multiple.
- Machine binding: tokens often include machine_hash = MD5(volumeSerial + productId + ...). \
  Self-signing requires reproducing the exact hash algorithm.
- Minimal patching principle: prefer patching conditional jumps (jz->jmp, jnz->nop) over \
  replacing entire functions. This preserves the function's side effects (e.g., initializing \
  data structures that later code depends on).
- IPC dependency trap: bypassing a validation check may succeed but the app crashes because \
  it also initializes IPC state. The validation function's SIDE EFFECTS matter.
- Startup sequence matters: token check, startup verify, license check may run in order. \
  All three must pass (or be bypassed) for the app to start.

Binary Info:
{binary_info}

Validation Functions (addresses):
{validation_functions}

Disassembly of Validation Code:
{disassembly}

Exit Code References:
{exit_codes}

String References:
{strings}

Tasks:
1. Map ALL validation checkpoints in the startup sequence (not just the first one).
2. For each checkpoint:
   - What it validates (token, license, hardware binding, expiry, signature)
   - How it fails (exit code, exception, return false)
   - What side effects it has (initialization, state setup)
   - Minimal patch to bypass (prefer conditional jump patches over function replacement)
3. Identify the token/license format:
   - Encryption algorithm and key derivation
   - Required fields and their sources
   - Machine binding mechanism
4. Assess self-signing feasibility: can we generate valid tokens locally?
5. Identify the MINIMUM set of patches needed for standalone operation.
6. Warn about IPC/state dependencies that patching might break.

Output as structured JSON with "checkpoints" (ordered array), "token_format", \
"machine_binding", "patch_plan", and "risks" fields."""
