"""Prompt Templates - Task-specific LLM prompts for reverse engineering analysis.

Inspired by r2ai's named prompt template system (-vulns, -autoname, etc.).
Each template takes structured input from FridaPilot tools and produces
a focused analysis prompt for the LLM.

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
1. Identify the encryption algorithm(s) used (AES, DES, RSA, ChaCha20, custom, etc.).
2. Determine the mode of operation (CBC, GCM, ECB, CTR, etc.).
3. Assess key management:
   - How are keys generated/stored/derived?
   - Is the key protection adequate for the protection level?
   - Are there hardcoded keys, IVs, or salts?
4. Identify weaknesses:
   - Weak algorithms (DES, RC4, MD5 for hashing)
   - ECB mode usage
   - Missing/static IVs
   - Insufficient key derivation (low iteration count)
   - Predictable key material
5. Suggest the optimal attack strategy based on the protection level.
6. If keys can be extracted, describe the extraction method.

Output as structured JSON with "algorithms", "key_management", "weaknesses", \
"attack_strategy", and "recommendations" fields."""


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

Captured Messages:
{messages}

Binary Analysis:
{binary_info}

String References:
{strings}

Related Functions:
{functions}

Tasks:
1. Identify the protocol type (binary/JSON/protobuf/msgpack/custom).
2. Map out the message format:
   - Header structure (magic bytes, length, type, flags)
   - Payload encoding
   - Encryption/compression layer (if any)
3. Enumerate message types and their purposes.
4. Identify the handshake/initialization sequence.
5. Document the request-response pattern.
6. Note any authentication/encryption mechanisms.

Output as structured JSON with "protocol_type", "message_format", \
"message_types", "handshake", and "security" fields."""
