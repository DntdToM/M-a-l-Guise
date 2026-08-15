# Plan v4 (FINAL): #18 CFG_EDGE_REDIVIDE + #19 SEMANTIC_NOP_INJECT

> [!IMPORTANT]
> **Phê duyệt bởi mentor. Đây là plan chốt hạ.** Mọi Open Questions đã được trả lời.

---

## Quyết định chốt từ mentor

| Câu hỏi | Quyết định | Lý do |
|---|---|---|
| Disassembly tool? | **angr 9.2.213** (CẤM Capstone) | angr build CFG recursive, chính xác hơn Capstone linear sweep |
| PE32/PE64 NOP? | **BẮT BUỘC tách** `_NOP_TEMPLATES_32` / `_NOP_TEMPLATES_64` | 0x40-0x4F = REX prefix trên x64, dùng nhầm inc/dec → crash |
| Dataset? | **Malware thật** | Mọi logic bọc `try...except` toàn hàm, return `original_bytes` khi lỗi |

---

## Kiến trúc tổng thể

```
MalwareEnv.reset()
  │
  ├─ angr.Project(pe_path)     ← Load PE 1 lần
  ├─ CFGFast()                 ← Build CFG 1 lần
  └─ _call_sites = [RVA list]  ← Cache CALL sites
  
MalwareEnv.step(action=#18)
  │
  ├─ site = random.choice(_call_sites)   ← Chọn từ cache
  ├─ LIEF: patch E8→E9 tại site          ← Vá bytes
  ├─ LIEF: ghi bridge code vào slack/section mới
  └─ _bridge_registry.append(...)        ← Đăng ký cho #19

MalwareEnv.step(action=#19)
  │
  ├─ Đọc _bridge_registry
  ├─ Mode A (chain): chèn NOP vào vmid bridge
  ├─ Mode B (standalone): chèn NOP vào slack
  └─ Check budget ≤ 5% original size
```

---

## NOP Templates — Tách PE32/PE64

### PE32 Templates (4 nhóm theo paper)

```python
_NOP_TEMPLATES_32 = {
    # ── Nhóm 1: Arithmetic ──
    'arithmetic': [
        b'\x40\x48',                        # inc eax; dec eax              (2B)
        b'\x41\x49',                        # inc ecx; dec ecx              (2B)
        b'\x42\x4a',                        # inc edx; dec edx              (2B)
        b'\x83\xc0\x01\x83\xe8\x01',        # add eax,1; sub eax,1          (6B)
        b'\x83\xc1\x02\x83\xe9\x02',        # add ecx,2; sub ecx,2          (6B)
    ],
    # ── Nhóm 2: Logical ──
    'logical': [
        b'\x09\xc0',                        # or eax, eax                    (2B)
        b'\x21\xc0',                        # and eax, eax                   (2B)
        b'\x09\xc9',                        # or ecx, ecx                    (2B)
        b'\x21\xc9',                        # and ecx, ecx                   (2B)
    ],
    # ── Nhóm 3: Comparison ──
    'comparison': [
        b'\x39\xc0',                        # cmp eax, eax                   (2B)
        b'\x85\xc0',                        # test eax, eax                  (2B)
        b'\x39\xc9',                        # cmp ecx, ecx                   (2B)
        b'\x85\xc9',                        # test ecx, ecx                  (2B)
    ],
    # ── Nhóm 4: Data Transfer ──
    'data_transfer': [
        b'\x50\x58',                        # push eax; pop eax              (2B)
        b'\x51\x59',                        # push ecx; pop ecx              (2B)
        b'\x52\x5a',                        # push edx; pop edx              (2B)
        b'\x53\x5b',                        # push ebx; pop ebx              (2B)
        b'\x56\x5e',                        # push esi; pop esi              (2B)
        b'\x57\x5f',                        # push edi; pop edi              (2B)
        b'\x89\xc0',                        # mov eax, eax                   (2B)
        b'\x87\xc0',                        # xchg eax, eax                  (2B)
    ],
}
```

### PE64 Templates (4 nhóm — KHÔNG có 0x40-0x4F)

```python
_NOP_TEMPLATES_64 = {
    # ── Nhóm 1: Arithmetic ──
    # 0x40-0x4F = REX prefix trên x64 → CẤM dùng inc/dec dạng short
    # Phải dùng dạng ModR/M: FF /0 (inc), FF /1 (dec)
    'arithmetic': [
        b'\xff\xc0\xff\xc8',                # inc eax; dec eax  (ModR/M)    (4B)
        b'\xff\xc1\xff\xc9',                # inc ecx; dec ecx              (4B)
        b'\x83\xc0\x01\x83\xe8\x01',        # add eax,1; sub eax,1          (6B)
        b'\x83\xc1\x02\x83\xe9\x02',        # add ecx,2; sub ecx,2          (6B)
    ],
    # ── Nhóm 2: Logical ──
    'logical': [
        b'\x09\xc0',                        # or eax, eax                    (2B)
        b'\x21\xc0',                        # and eax, eax                   (2B)
        b'\x09\xc9',                        # or ecx, ecx                    (2B)
        b'\x21\xc9',                        # and ecx, ecx                   (2B)
    ],
    # ── Nhóm 3: Comparison ──
    'comparison': [
        b'\x39\xc0',                        # cmp eax, eax                   (2B)
        b'\x85\xc0',                        # test eax, eax                  (2B)
        b'\x39\xc9',                        # cmp ecx, ecx                   (2B)
        b'\x85\xc9',                        # test ecx, ecx                  (2B)
    ],
    # ── Nhóm 4: Data Transfer ──
    'data_transfer': [
        b'\x50\x58',                        # push rax; pop rax              (2B)
        b'\x51\x59',                        # push rcx; pop rcx              (2B)
        b'\x52\x5a',                        # push rdx; pop rdx              (2B)
        b'\x53\x5b',                        # push rbx; pop rbx              (2B)
        b'\x56\x5e',                        # push rsi; pop rsi              (2B)
        b'\x57\x5f',                        # push rdi; pop rdi              (2B)
        b'\x89\xc0',                        # mov eax, eax                   (2B)
        b'\x48\x89\xc0',                    # mov rax, rax (REX.W)           (3B)
        b'\x87\xc0',                        # xchg eax, eax                  (2B)
    ],
}
```

> [!CAUTION]
> **0x40-0x4F trên x64**: `0x40` = REX prefix (không phải `inc eax`), `0x48` = REX.W (64-bit operand size). Nếu chèn `\x40\x48` vào PE64, CPU sẽ decode `0x40` như REX → instruction tiếp theo bị decode sai → **crash logic chắc chắn**.

---

## angr Integration — Tại `MalwareEnv.reset()`

```python
import angr
import struct

def reset(self, ...):
    ...
    # ── Clear per-episode state ──
    self.action_manager._bridge_registry.clear()
    self.action_manager._total_nop_bytes_injected = 0
    self.action_manager._agent_created_sections.clear()

    # ── Load PE ──
    self.pe_bytes = open(self.malware_path, 'rb').read()

    # ── angr: Build CFG 1 lần, cache CALL sites ──
    try:
        proj = angr.Project(
            self.malware_path,
            auto_load_libs=False,
            load_options={'main_opts': {'base_addr': 0}}  # load at 0 for RVA
        )
        cfg = proj.analyses.CFGFast()

        call_sites = []
        for node in cfg.graph.nodes():
            if node.block is None:
                continue
            for insn in node.block.capstone.insns:
                # angr dùng capstone internally → CS_GRP_CALL
                if insn.mnemonic == 'call':
                    # Chỉ lấy near relative call (E8)
                    raw = insn.bytes
                    if len(raw) >= 1 and raw[0] == 0xE8 and insn.size == 5:
                        call_sites.append({
                            'rva': insn.address,
                            'size': insn.size,
                        })
        self.action_manager._call_sites = call_sites
    except Exception as exc:
        logger.warning("angr CFG analysis failed: %s; no CALL sites", exc)
        self.action_manager._call_sites = []

    # ── Detect PE type ──
    try:
        pe = lief.PE.parse(list(self.pe_bytes))
        self.action_manager._is_pe64 = (
            pe is not None and
            pe.optional_header.magic == lief.PE.PE_TYPE.PE32_PLUS
        )
    except Exception:
        self.action_manager._is_pe64 = False
    ...
```

---

## #18 CFG_EDGE_REDIVIDE — Pseudocode

```python
def _cfg_edge_redivide(self, bytez: bytes) -> bytes:
    original_bytes = bytes(bytez)
    try:
        # 1. Có CALL sites không?
        if not self._call_sites:
            return original_bytes

        pe = lief.PE.parse(list(original_bytes))
        if pe is None:
            return original_bytes

        # 2. Chọn 1 call site random
        site = random.choice(self._call_sites)
        call_rva = site['rva']

        # 3. Tìm .text section
        text_section = None
        for s in pe.sections:
            sec_rva = s.virtual_address
            if sec_rva <= call_rva < sec_rva + s.virtual_size:
                text_section = s
                break
        if text_section is None:
            return original_bytes

        # 4. Đọc original CALL displacement
        call_offset_in_sec = call_rva - text_section.virtual_address
        text_content = bytearray(text_section.content)
        if text_content[call_offset_in_sec] != 0xE8:
            return original_bytes  # Verify E8
        original_disp = struct.unpack_from('<i', text_content, call_offset_in_sec + 1)[0]
        original_target_rva = call_rva + 5 + original_disp
        vpost_rva = call_rva + 5

        # 5. Tìm không gian cho bridge (Algorithm 2: slack vs new section)
        BRIDGE_SIZE = 15  # placeholder(5) + CALL(5) + JMP(5)
        bridge_section, bridge_rva = _find_bridge_space(pe, BRIDGE_SIZE)
        if bridge_section is None:
            return original_bytes

        # 6. Xây bridge code tại bridge_rva
        nop_placeholder = b'\x0f\x1f\x44\x00\x00'  # 5-byte NOP (placeholder cho #19)
        call_instr = _encode_rel32(0xE8, bridge_rva + 5, original_target_rva)
        jmp_back   = _encode_rel32(0xE9, bridge_rva + 10, vpost_rva)
        bridge_code = nop_placeholder + call_instr + jmp_back

        # 7. Ghi bridge code
        bridge_content = bytearray(bridge_section.content)
        bridge_offset_in_sec = bridge_rva - bridge_section.virtual_address
        # Pad nếu cần
        while len(bridge_content) < bridge_offset_in_sec + BRIDGE_SIZE:
            bridge_content.append(0)
        bridge_content[bridge_offset_in_sec:bridge_offset_in_sec + BRIDGE_SIZE] = bridge_code
        bridge_section.content = list(bridge_content)
        if bridge_offset_in_sec + BRIDGE_SIZE > bridge_section.virtual_size:
            bridge_section.virtual_size = bridge_offset_in_sec + BRIDGE_SIZE

        # 8. Patch .text: E8 → E9 (JMP to bridge)
        jmp_to_bridge = _encode_rel32(0xE9, call_rva, bridge_rva)
        text_content[call_offset_in_sec:call_offset_in_sec + 5] = jmp_to_bridge
        text_section.content = list(text_content)

        # 9. Đăng ký bridge cho #19
        self._bridge_registry.append({
            'section_name': bridge_section.name,
            'bridge_rva': bridge_rva,
            'nop_offset': 0,         # offset trong bridge
            'nop_size': 5,           # placeholder hiện tại
            'call_offset': 5,
            'jmp_back_offset': 10,
            'total_size': BRIDGE_SIZE,
            'vpost_rva': vpost_rva,
        })

        # 10. Remove used call site từ cache
        self._call_sites.remove(site)

        result = _safe_build(pe)
        return result if result else original_bytes

    except Exception as exc:
        logger.warning("CFG_EDGE_REDIVIDE failed: %s", exc)
        return original_bytes
```

---

## #19 SEMANTIC_NOP_INJECT — Pseudocode

```python
def _semantic_nop_inject(self, bytez: bytes) -> bytes:
    original_bytes = bytes(bytez)
    try:
        pe = lief.PE.parse(list(original_bytes))
        if pe is None:
            return original_bytes

        # Budget check (5% cap — paper §4.1.5)
        max_budget = len(original_bytes) * 5 // 100
        remaining = max_budget - self._total_nop_bytes_injected
        if remaining <= 1:
            return original_bytes

        # Chọn template set theo PE type
        templates = _NOP_TEMPLATES_64 if self._is_pe64 else _NOP_TEMPLATES_32

        # Chọn 1-3 templates random từ random family
        nop_bytes = b''
        for _ in range(random.randint(1, 3)):
            family = random.choice(list(templates.keys()))
            template = random.choice(templates[family])
            if len(nop_bytes) + len(template) > remaining:
                break
            nop_bytes += template
        if not nop_bytes:
            return original_bytes

        # ── Mode A: Chain (chèn vào vmid bridge) ──
        if self._bridge_registry:
            bridge = random.choice(self._bridge_registry)
            section = _find_section_by_name(pe, bridge['section_name'])
            if section is None:
                return original_bytes

            content = bytearray(section.content)
            # Chèn NOP TRƯỚC call trong bridge (tại nop_offset)
            insert_pos = (bridge['bridge_rva'] - section.virtual_address
                          + bridge['nop_offset'] + bridge['nop_size'])
            content[insert_pos:insert_pos] = nop_bytes  # insert (không overwrite)

            # Cập nhật JMP back displacement (bị đẩy xuống len(nop_bytes))
            jmp_pos = (bridge['bridge_rva'] - section.virtual_address
                       + bridge['jmp_back_offset'] + len(nop_bytes))
            old_disp = struct.unpack_from('<i', content, jmp_pos + 1)[0]
            new_disp = old_disp - len(nop_bytes)
            struct.pack_into('<i', content, jmp_pos + 1, new_disp)

            section.content = list(content)
            if len(content) > section.virtual_size:
                section.virtual_size = len(content)

            # Cập nhật bridge registry
            bridge['nop_size'] += len(nop_bytes)
            bridge['call_offset'] += len(nop_bytes)
            bridge['jmp_back_offset'] += len(nop_bytes)
            bridge['total_size'] += len(nop_bytes)

        # ── Mode B: Standalone (chèn vào slack space) ──
        else:
            candidates = []
            for s in pe.sections:
                slack = s.sizeof_raw_data - s.virtual_size
                if slack >= len(nop_bytes):
                    candidates.append(s)
            if not candidates:
                return original_bytes

            target = random.choice(candidates)
            content = bytearray(target.content)
            while len(content) < target.virtual_size:
                content.append(0)
            content.extend(nop_bytes)
            target.content = list(content)
            target.virtual_size = len(content)

        self._total_nop_bytes_injected += len(nop_bytes)

        result = _safe_build(pe)
        return result if result else original_bytes

    except Exception as exc:
        logger.warning("SEMANTIC_NOP_INJECT failed: %s", exc)
        return original_bytes
```

---

## Helper functions

```python
def _encode_rel32(opcode: int, from_rva: int, to_rva: int) -> bytes:
    """Encode E8 (CALL near) hoặc E9 (JMP near) với signed displacement."""
    disp = to_rva - from_rva - 5
    return bytes([opcode]) + struct.pack('<i', disp)

def _find_bridge_space(pe, size_needed: int):
    """Tìm slack space cho bridge code. Trả về (section, rva) hoặc (None, 0).
    Algorithm 2: slack trước, section mới nếu hết."""
    for s in pe.sections:
        slack = s.sizeof_raw_data - s.virtual_size
        if slack >= size_needed:
            bridge_rva = s.virtual_address + s.virtual_size
            return s, bridge_rva
    return None, 0

def _find_section_by_name(pe, name: str):
    """Tìm section theo tên."""
    for s in pe.sections:
        if s.name == name:
            return s
    return None
```

---

## State mới trong PEMutator.__init__

```python
self._bridge_registry: list = []         # Bridge locations cho #19
self._total_nop_bytes_injected: int = 0  # NOP budget tracking (5% cap)
self._call_sites: list = []              # Cached từ angr (set bởi MalwareEnv)
self._is_pe64: bool = False              # PE type (set bởi MalwareEnv)
# Đã có:
# self._agent_created_sections: set = set()
```

## Reset trong MalwareEnv

```python
self.action_manager._bridge_registry.clear()
self.action_manager._total_nop_bytes_injected = 0
self.action_manager._agent_created_sections.clear()   # Đã có
self.action_manager._call_sites = []                   # Set bởi angr bên dưới
self.action_manager._is_pe64 = False                   # Set bởi LIEF bên dưới
```

---

## Thứ tự code thực hiện

| Bước | Công việc | File |
|:---:|---|---|
| 1 | Thêm `_NOP_TEMPLATES_32`, `_NOP_TEMPLATES_64` constants | pe_mutator.py |
| 2 | Thêm `_encode_rel32()`, `_find_bridge_space()`, `_find_section_by_name()` helpers | pe_mutator.py |
| 3 | Thêm state mới vào `__init__`: `_bridge_registry`, `_total_nop_bytes_injected`, `_call_sites`, `_is_pe64` | pe_mutator.py |
| 4 | Implement `_cfg_edge_redivide` (#18) — replace stub | pe_mutator.py |
| 5 | Implement `_semantic_nop_inject` (#19) — replace stub | pe_mutator.py |
| 6 | Update `MalwareEnv.reset()` — angr load + clear state | malware_env.py |
| 7 | Cập nhật smoke test | pe_mutator.py |
| 8 | Test trên PE thật | terminal |

## Verification Plan

1. **Unit test**: Smoke test trên PE thật (malware dataset)
2. **Chain test**: `#8 (section_add) → #18 → #19` → verify PE valid
3. **Budget test**: Chạy #19 nhiều lần → verify tổng NOP ≤ 5% original size
4. **PE32/PE64**: Test trên cả 2 loại file → verify đúng template set
5. **Error handling**: Feed garbage bytes → verify return original_bytes
