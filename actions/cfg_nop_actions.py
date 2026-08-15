"""
CFG/NOP mutation actions — MalGuise-based call-based redividing.

Contains action #17 (CFG_EDGE_REDIVIDE) and #18 (SEMANTIC_NOP_INJECT).
Ref: Ling et al., "A Wolf in Sheep's Clothing", USENIX Security 2024.

This is a standalone action class (like PackerTransform / DarkarmourXORTransformAction).
PEMutator delegates to an instance of this class via thin wrapper methods.

External state set by MalwareEnv.reset() each episode:
  - _call_sites  : list[dict]  — near E8 CALL RVAs (cached from angr CFGFast)
  - _is_pe64     : bool        — PE32 vs PE64 (determines NOP template set)
  - _bridge_registry            — reset per episode
  - _total_nop_bytes_injected   — reset per episode
"""

from __future__ import annotations

import logging
import random
import struct
from typing import Callable, List, Optional

import lief

logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════
# NOP Template Library — 4 families (MalGuise §4.1.5)
#
# PE32 and PE64 MUST use separate templates.
# 0x40-0x4F = REX prefix on x64, NOT inc/dec short form.
# ══════════════════════════════════════════════════════════════════════

_NOP_TEMPLATES_32 = {
    "arithmetic": [
        b"\x40\x48",                        # inc eax; dec eax              (2B)
        b"\x41\x49",                        # inc ecx; dec ecx              (2B)
        b"\x42\x4a",                        # inc edx; dec edx              (2B)
        b"\x83\xc0\x01\x83\xe8\x01",        # add eax,1; sub eax,1          (6B)
        b"\x83\xc1\x02\x83\xe9\x02",        # add ecx,2; sub ecx,2          (6B)
    ],
    "logical": [
        b"\x09\xc0",                        # or eax, eax                    (2B)
        b"\x21\xc0",                        # and eax, eax                   (2B)
        b"\x09\xc9",                        # or ecx, ecx                    (2B)
        b"\x21\xc9",                        # and ecx, ecx                   (2B)
    ],
    "comparison": [
        b"\x39\xc0",                        # cmp eax, eax                   (2B)
        b"\x85\xc0",                        # test eax, eax                  (2B)
        b"\x39\xc9",                        # cmp ecx, ecx                   (2B)
        b"\x85\xc9",                        # test ecx, ecx                  (2B)
    ],
    "data_transfer": [
        b"\x50\x58",                        # push eax; pop eax              (2B)
        b"\x51\x59",                        # push ecx; pop ecx              (2B)
        b"\x52\x5a",                        # push edx; pop edx              (2B)
        b"\x53\x5b",                        # push ebx; pop ebx              (2B)
        b"\x56\x5e",                        # push esi; pop esi              (2B)
        b"\x57\x5f",                        # push edi; pop edi              (2B)
        b"\x89\xc0",                        # mov eax, eax                   (2B)
        b"\x87\xc0",                        # xchg eax, eax                  (2B)
    ],
}

_NOP_TEMPLATES_64 = {
    # 0x40-0x4F = REX prefix on x64 → use ModR/M form for inc/dec
    "arithmetic": [
        b"\xff\xc0\xff\xc8",                # inc eax; dec eax  (ModR/M)    (4B)
        b"\xff\xc1\xff\xc9",                # inc ecx; dec ecx              (4B)
        b"\x83\xc0\x01\x83\xe8\x01",        # add eax,1; sub eax,1          (6B)
        b"\x83\xc1\x02\x83\xe9\x02",        # add ecx,2; sub ecx,2          (6B)
    ],
    "logical": [
        b"\x09\xc0",                        # or eax, eax                    (2B)
        b"\x21\xc0",                        # and eax, eax                   (2B)
        b"\x09\xc9",                        # or ecx, ecx                    (2B)
        b"\x21\xc9",                        # and ecx, ecx                   (2B)
    ],
    "comparison": [
        b"\x39\xc0",                        # cmp eax, eax                   (2B)
        b"\x85\xc0",                        # test eax, eax                  (2B)
        b"\x39\xc9",                        # cmp ecx, ecx                   (2B)
        b"\x85\xc9",                        # test ecx, ecx                  (2B)
    ],
    "data_transfer": [
        b"\x50\x58",                        # push rax; pop rax              (2B)
        b"\x51\x59",                        # push rcx; pop rcx              (2B)
        b"\x52\x5a",                        # push rdx; pop rdx              (2B)
        b"\x53\x5b",                        # push rbx; pop rbx              (2B)
        b"\x56\x5e",                        # push rsi; pop rsi              (2B)
        b"\x57\x5f",                        # push rdi; pop rdi              (2B)
        b"\x89\xc0",                        # mov eax, eax                   (2B)
        b"\x48\x89\xc0",                    # mov rax, rax (REX.W)           (3B)
        b"\x87\xc0",                        # xchg eax, eax                  (2B)
    ],
}


# ══════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════

def _encode_rel32(opcode: int, from_rva: int, to_rva: int) -> bytes:
    """Encode a near CALL (E8) or JMP (E9) with signed rel32 displacement."""
    disp = to_rva - from_rva - 5
    return bytes([opcode]) + struct.pack("<i", disp)


def _is_executable_section(section: lief.PE.Section) -> bool:
    return bool(int(section.characteristics) & int(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE))


def _find_bridge_space(pe: lief.PE.Binary, size_needed: int):
    """Find executable slack for bridge code, fall back to a new code section.

    Follows MalGuise Algorithm 2: slack space first, new section if not enough.
    """
    # Try existing executable sections' slack space first
    for section in pe.sections:
        if not _is_executable_section(section):
            continue
        slack = section.sizeof_raw_data - section.virtual_size
        if slack >= size_needed:
            bridge_rva = section.virtual_address + section.virtual_size
            return section, bridge_rva

    # Fall back: create a new executable section
    section = lief.PE.Section()
    existing_names = {s.name for s in pe.sections}
    for idx in range(100):
        candidate = ".cfgbrg" if idx == 0 else f".c18{idx:02d}"
        if candidate not in existing_names:
            section.name = candidate
            break
    else:
        return None, 0

    section.content = [0x90] * size_needed
    section.characteristics = (
        int(lief.PE.Section.CHARACTERISTICS.CNT_CODE)
        | int(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE)
        | int(lief.PE.Section.CHARACTERISTICS.MEM_READ)
    )

    added_section = pe.add_section(section)
    if added_section is None:
        return None, 0

    return added_section, added_section.virtual_address


def _find_section_by_name(pe: lief.PE.Binary, name: str):
    """Find a PE section by exact name."""
    for section in pe.sections:
        if section.name == name:
            return section
    return None


# ══════════════════════════════════════════════════════════════════════
# CfgNopActions — standalone action class
# ══════════════════════════════════════════════════════════════════════

class CfgNopActions:
    """Action #17 (CFG_EDGE_REDIVIDE) + #18 (SEMANTIC_NOP_INJECT).

    Standalone class following the same delegate pattern as PackerTransform
    and DarkarmourXORTransformAction.  PEMutator instantiates this class
    and delegates via thin wrapper methods.

    Per-episode state (set by MalwareEnv.reset):
        _call_sites              — list of {rva, size} dicts from angr
        _is_pe64                 — determines NOP template set
        _bridge_registry         — bridges created by #17 for #18 to use
        _total_nop_bytes_injected — NOP budget tracking (≤5% of original)
    """

    def __init__(
        self,
        safe_build_fn: Callable[[lief.PE.Binary], Optional[bytes]] = None,
    ) -> None:
        def default_safe_build(pe: lief.PE.Binary) -> Optional[bytes]:
            try:
                builder = lief.PE.Builder(pe, lief.PE.Builder.config_t())
                builder.build()
                return bytes(builder.bytes())
            except Exception as e:
                logger.error(f"LIEF build error: {e}")
                return None
        self._safe_build = safe_build_fn or default_safe_build

        # Per-episode state (cleared in MalwareEnv.reset)
        self._call_sites: List[dict] = []
        self._is_pe64: bool = False
        self._bridge_registry: list = []
        self._total_nop_bytes_injected: int = 0

    def reset_episode(self) -> None:
        """Clear all per-episode state. Called by MalwareEnv.reset()."""
        self._call_sites = []
        self._is_pe64 = False
        self._bridge_registry.clear()
        self._total_nop_bytes_injected = 0

    # ── 17. CFG_EDGE_REDIVIDE ────────────────────────────────────────

    def cfg_edge_redivide(self, bytez: bytes) -> bytes:
        """Split a cached near-CALL edge through a bridge block (vfore/vmid/vpost).

        MalGuise Algorithm 3: Patch E8 (CALL near) → E9 (JMP near) to bridge,
        bridge contains [CALL original][JMP back to vpost]. Semantic NOPs are
        inserted later by action #18 between CALL and JMP.
        """
        original_bytes = bytes(bytez)

        try:
            if not self._call_sites:
                logger.debug("CFG_EDGE_REDIVIDE skipped: no cached CALL sites.")
                return original_bytes

            pe = lief.PE.parse(original_bytes)
            if pe is None:
                logger.debug("CFG_EDGE_REDIVIDE skipped: LIEF returned no PE binary.")
                return original_bytes

            # Pick 1 call site (random — DDDQN agent is the search strategy)
            site = random.choice(self._call_sites)
            call_rva = int(site.get("rva", 0) if isinstance(site, dict) else site)
            if call_rva <= 0:
                return original_bytes

            # Find the section containing this CALL
            text_section = None
            for section in pe.sections:
                section_start = section.virtual_address
                section_end = section_start + section.virtual_size
                if section_start <= call_rva < section_end:
                    text_section = section
                    break
            if text_section is None:
                logger.debug("CFG_EDGE_REDIVIDE skipped: CALL RVA is outside sections.")
                return original_bytes

            # Verify E8 at the call site
            call_offset_in_sec = call_rva - text_section.virtual_address
            text_content = bytearray(text_section.content)
            if call_offset_in_sec < 0 or call_offset_in_sec + 5 > len(text_content):
                return original_bytes
            if text_content[call_offset_in_sec] != 0xE8:
                logger.debug("CFG_EDGE_REDIVIDE skipped: cached site is not an E8 near CALL.")
                return original_bytes

            # Read original displacement and compute target RVA
            original_disp = struct.unpack_from("<i", text_content, call_offset_in_sec + 1)[0]
            original_target_rva = call_rva + 5 + original_disp
            vpost_rva = call_rva + 5

            # Find bridge space (Algorithm 2: slack → new section)
            bridge_size = 10  # CALL(5) + JMP(5)
            bridge_section, bridge_rva = _find_bridge_space(pe, bridge_size)
            if bridge_section is None:
                logger.debug("CFG_EDGE_REDIVIDE skipped: no bridge storage available.")
                return original_bytes

            # Build bridge code: [CALL target] [JMP vpost]
            bridge_code = (
                _encode_rel32(0xE8, bridge_rva, original_target_rva)
                + _encode_rel32(0xE9, bridge_rva + 5, vpost_rva)
            )

            # Write bridge code into the bridge section
            bridge_offset_in_sec = bridge_rva - bridge_section.virtual_address
            bridge_content = bytearray(bridge_section.content)
            while len(bridge_content) < bridge_offset_in_sec + bridge_size:
                bridge_content.append(0)
            bridge_content[bridge_offset_in_sec:bridge_offset_in_sec + bridge_size] = bridge_code
            bridge_section.content = list(bridge_content)
            if bridge_offset_in_sec + bridge_size > bridge_section.virtual_size:
                bridge_section.virtual_size = bridge_offset_in_sec + bridge_size

            # Patch .text: replace E8 (CALL) with E9 (JMP) to bridge
            text_content[call_offset_in_sec:call_offset_in_sec + 5] = _encode_rel32(
                0xE9, call_rva, bridge_rva,
            )
            text_section.content = list(text_content)

            # Build PE
            result = self._safe_build(pe)
            if not result:
                return original_bytes

            # Register bridge for #18 to use
            self._bridge_registry.append({
                "section_name": bridge_section.name,
                "bridge_rva": bridge_rva,
                "nop_offset": 5,
                "nop_size": 0,
                "call_offset": 0,
                "jmp_back_offset": 5,
                "total_size": bridge_size,
                "vpost_rva": vpost_rva,
                "original_target_rva": original_target_rva,
            })

            # Remove used call site from cache (don't split same call twice)
            try:
                self._call_sites.remove(site)
            except ValueError:
                pass

            return result

        except Exception as exc:
            logger.warning(
                "CFG_EDGE_REDIVIDE failed; returning original bytes: %s",
                exc,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )
            return original_bytes

    # ── 18. SEMANTIC_NOP_INJECT ──────────────────────────────────────

    def semantic_nop_inject(self, bytez: bytes) -> bytes:
        """Inject semantic NOP templates into a bridge (vmid) or executable slack.

        Mode A (chain): If _bridge_registry has entries, inject NOPs into vmid
                        — exactly as MalGuise §3.2.1 describes.
        Mode B (standalone): If no bridges exist, inject into executable
                             slack or a newly added code section.

        NOP budget is capped at 5% of original file size (MalGuise §4.1.5).
        """
        original_bytes = bytes(bytez)

        try:
            pe = lief.PE.parse(original_bytes)
            if pe is None:
                logger.debug("SEMANTIC_NOP_INJECT skipped: LIEF returned no PE binary.")
                return original_bytes

            # Budget check (5% cap — MalGuise §4.1.5)
            max_budget = len(original_bytes) * 5 // 100
            remaining = max_budget - self._total_nop_bytes_injected
            if remaining <= 1:
                logger.debug("SEMANTIC_NOP_INJECT skipped: NOP budget exhausted.")
                return original_bytes

            # Select template set based on PE type
            current_is_pe64 = pe.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS
            self._is_pe64 = current_is_pe64
            templates = _NOP_TEMPLATES_64 if current_is_pe64 else _NOP_TEMPLATES_32

            # Pick 1-3 templates from random families
            nop_bytes = b""
            for _ in range(random.randint(1, 3)):
                family = random.choice(list(templates.keys()))
                candidates = [
                    template for template in templates[family]
                    if len(nop_bytes) + len(template) <= remaining
                ]
                if not candidates:
                    break
                nop_bytes += random.choice(candidates)
            if not nop_bytes:
                return original_bytes

            bridge_update = None

            # ── Mode A: Chain — inject into vmid bridge ──
            if self._bridge_registry:
                bridge = random.choice(self._bridge_registry)
                section = _find_section_by_name(pe, bridge["section_name"])
                if section is None:
                    logger.debug("SEMANTIC_NOP_INJECT skipped: registered bridge section missing.")
                    return original_bytes

                bridge_base = bridge["bridge_rva"] - section.virtual_address
                if bridge_base < 0:
                    return original_bytes

                content = bytearray(section.content)
                required_len = bridge_base + bridge["total_size"]
                while len(content) < required_len:
                    content.append(0)

                # Insert semantic NOPs between CALL and JMP, matching MalGuise.
                insert_pos = bridge_base + bridge["nop_offset"] + bridge["nop_size"]
                if insert_pos > len(content):
                    content.extend(b"\x00" * (insert_pos - len(content)))
                content[insert_pos:insert_pos] = nop_bytes  # insert, not overwrite

                # CALL stays in place; only the trailing JMP shifts forward.
                call_pos = bridge_base + bridge["call_offset"]
                jmp_pos = bridge_base + bridge["jmp_back_offset"] + len(nop_bytes)
                if call_pos + 5 > len(content) or jmp_pos + 5 > len(content):
                    return original_bytes
                if content[call_pos] != 0xE8 or content[jmp_pos] != 0xE9:
                    logger.debug("SEMANTIC_NOP_INJECT skipped: bridge CALL/JMP marker mismatch.")
                    return original_bytes

                jmp_disp = struct.unpack_from("<i", content, jmp_pos + 1)[0]
                struct.pack_into("<i", content, jmp_pos + 1, jmp_disp - len(nop_bytes))

                section.content = list(content)
                new_bridge_size = bridge["total_size"] + len(nop_bytes)
                used_size = bridge_base + new_bridge_size
                if used_size > section.virtual_size:
                    section.virtual_size = used_size

                bridge_update = (bridge, len(nop_bytes))

            # ── Mode B: Standalone — inject into executable slack / new code section ──
            else:
                target, injection_rva = _find_bridge_space(pe, len(nop_bytes))
                if target is None:
                    logger.debug("SEMANTIC_NOP_INJECT skipped: no executable injection space available.")
                    return original_bytes

                content = bytearray(target.content)
                injection_offset = injection_rva - target.virtual_address
                while len(content) < injection_offset + len(nop_bytes):
                    content.append(0)
                content[injection_offset:injection_offset + len(nop_bytes)] = nop_bytes
                target.content = list(content)
                if injection_offset + len(nop_bytes) > target.virtual_size:
                    target.virtual_size = injection_offset + len(nop_bytes)

            # Build PE
            result = self._safe_build(pe)
            if not result:
                return original_bytes

            # Update tracking state only after successful build
            self._total_nop_bytes_injected += len(nop_bytes)
            if bridge_update:
                bridge, delta = bridge_update
                bridge["nop_size"] += delta
                bridge["jmp_back_offset"] += delta
                bridge["total_size"] += delta

            return result

        except Exception as exc:
            logger.warning(
                "SEMANTIC_NOP_INJECT failed; returning original bytes: %s",
                exc,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )
            return original_bytes
